/*
 * This file is part of tcpflow by Simson Garfinkel <simsong@acm.org>.
 * Originally by Jeremy Elson <jelson@circlemud.org>.
 *
 * This source code is under the GNU Public License (GPL) version 3.
 * See COPYING for details.
 *
 */

#define __MAIN_C__

#include "config.h"
#include "tcpflow.h"
#include "tcpip.h"
#include "tcpdemux.h"
#include "greengrasssdk.h"

#include <string>
#include <vector>
#include <sys/types.h>
#include <zmq.hpp>
#include <boost/filesystem.hpp>
#include <msgpack.hpp>

int packet_buffer_timeout = 20;
scanner_info::scanner_config be_config; // system configuration

const char *progname = "tcpflow-gg";
int debug = 10; // DEFAULT_DEBUG_LEVEL;

/* semaphore prevents multiple copies from outputing on top of each other */
#ifdef HAVE_PTHREAD_H
#include <semaphore.h>
sem_t *semlock = 0;
#endif

scanner_t *scanners_builtin[] = { scan_tcpdemux, 0};

bool opt_no_promisc = false;		// true if we should not use promiscious mode

/* These must be global variables so they are available in the signal handler */
feature_recorder_set *the_fs = 0;
pcap_t *pd = 0;
void terminate(int sig) 
{
    if (sig == SIGHUP || sig == SIGINT || sig == SIGTERM) {
        DEBUG(1) ("terminating orderly");
        pcap_breakloop(pd);
        return;
    } else {
        DEBUG(1) ("terminating");
        be13::plugin::phase_shutdown(*the_fs);	// give plugins a chance to do a clean shutdown
        exit(0); /* libpcap uses onexit to clean up */
    }
}

#include <sys/wait.h>

#ifdef HAVE_INFLATER
static inflaters_t *inflaters = 0;
#endif
static int process_infile(tcpdemux &demux,const std::string &expression,std::string &device,const std::string &infile)
{
    char error[PCAP_ERRBUF_SIZE];
    int dlt=0;
    pcap_handler handler;
    int waitfor = -1;
    int pipefd = -1;

#ifdef HAVE_INFLATER
    if(inflaters==0) inflaters = build_inflaters();
#endif

    if (infile!=""){
        std::string file_path = infile;
        // decompress input if necessary
#ifdef HAVE_INFLATER
        for(inflaters_t::const_iterator it = inflaters->begin(); it != inflaters->end(); it++) {
            if((*it)->appropriate(infile)) {
                pipefd = (*it)->invoke(infile, &waitfor);
                if(pipefd < 0) {
                    std::cerr << "decompression of '" << infile << "' failed: " << strerror (errno) << std::endl;
                    exit(1);
                }
                file_path = ssprintf("/dev/fd/%d", pipefd);
                if(access(file_path.c_str(), R_OK)) {
                    std::cerr << "decompression of '" << infile << "' is not available on this system" << std::endl;
                    exit(1);
                }
                break;
            }
        }
#endif
	if ((pd = pcap_open_offline(file_path.c_str(), error)) == NULL){	/* open the capture file */
	    die("%s", error);
	}
	dlt = pcap_datalink(pd);	/* get the handler for this kind of packets */
	handler = find_handler(dlt, infile.c_str());
    } else {
	/* if the user didn't specify a device, try to find a reasonable one */
    if (device.empty()){
#ifdef HAVE_PCAP_FINDALLDEVS
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs = 0;
        if (pcap_findalldevs(&alldevs,errbuf)){
            die("%s", errbuf);
        }

        if (alldevs == 0) {
            die("found 0 devices, maybe you don't have permissions, switch to root or equivalent user instead.");
        }

        device.assign(alldevs[0].name);
        pcap_freealldevs(alldevs);
#else
        const char* dev = pcap_lookupdev(error);
        if (dev == NULL)
            die("%s", error);

        device.assign(dev);
#endif
    }

	/* make sure we can open the device */
	if ((pd = pcap_open_live(device.c_str(), SNAPLEN, !opt_no_promisc, packet_buffer_timeout, error)) == NULL){
	    die("%s", error);
	}
	/* get the handler for this kind of packets */
	dlt = pcap_datalink(pd);
	handler = find_handler(dlt, device.c_str());
    }

    DEBUG(20) ("filter expression: '%s'",expression.c_str());

    /* install the filter expression in libpcap */
    struct bpf_program	fcode;
    if (pcap_compile(pd, &fcode, expression.c_str(), 1, 0) < 0){
	die("%s", pcap_geterr(pd));
    }

    if (pcap_setfilter(pd, &fcode) < 0){
	die("%s", pcap_geterr(pd));
    }

    /* initialize our flow state structures */

    /* set up signal handlers for graceful exit (pcap uses onexit to put
     * interface back into non-promiscuous mode
     */
    portable_signal(SIGTERM, terminate);
    portable_signal(SIGINT, terminate);
#ifdef SIGHUP
    portable_signal(SIGHUP, terminate);
#endif

    /* start listening or reading from the input file */
    if (infile == "") DEBUG(1) ("listening on %s", device.c_str());
    int pcap_retval = pcap_loop(pd, -1, handler, (u_char *)tcpdemux::getInstance());

    if (pcap_retval < 0 && pcap_retval != -2){
	DEBUG(1) ("%s: %s", infile.c_str(),pcap_geterr(pd));
	return -1;
    }
    pcap_close (pd);
#ifdef HAVE_FORK
    if (waitfor != -1) {
        wait (0);
    }
    if (pipefd != -1) {
        close (pipefd);
    }
#endif

    return 0;
}

/* be_hash. Currently this just returns the MD5 of the sbuf,
 * but eventually it will allow the use of different hashes.
 */
static std::string be_hash_name("md5");
static std::string be_hash_func(const uint8_t *buf,size_t bufsize)
{
    if(be_hash_name=="md5" || be_hash_name=="MD5"){
        return md5_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(be_hash_name=="sha1" || be_hash_name=="SHA1" || be_hash_name=="sha-1" || be_hash_name=="SHA-1"){
        return sha1_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(be_hash_name=="sha256" || be_hash_name=="SHA256" || be_hash_name=="sha-256" || be_hash_name=="SHA-256"){
        return sha256_generator::hash_buf(buf,bufsize).hexdigest();
    }
    std::cerr << "Invalid hash name: " << be_hash_name << "\n";
    std::cerr << "This version of bulk_extractor only supports MD5, SHA1, and SHA256\n";
    exit(1);
}
static feature_recorder_set::hash_def be_hash(be_hash_name,be_hash_func);

void handler(const gg_lambda_context *cxt) {
    (void)cxt;
    return;
}

zmq::context_t *ctx = new zmq::context_t();
zmq::socket_t sock (*ctx, zmq::socket_type::pub);

struct ZMQ_MSG {
	std::vector<char> data;
	uint8_t src[16];
    uint8_t dst[16];
    uint16_t sport;
    uint16_t dport;
	MSGPACK_DEFINE_MAP(data, src, dst, sport, dport);
};

void send_via_zmq(char *payload, int size, const uint8_t src[], const uint8_t dst[], uint16_t sport, uint16_t dport) {
    struct ZMQ_MSG msg;

	msg.data = std::vector<char>(payload, payload + size);
    msg.sport = sport;
    msg.dport = dport;

	for(int i=0;i<16;i++) {
        msg.src[i] = src[i];
    }

    for(int i=0;i<16;i++) {
        msg.dst[i] = dst[i];
    }

	std::stringstream buffer;
	msgpack::pack(buffer, msg);
	buffer.seekg(0);
	std::string msg_str(buffer.str());

	sock.send(zmq::message_t(msg_str), zmq::send_flags::dontwait); 
}

int tcpflow(std::string device, std::string expression)
{
    sock.bind("tcp://127.0.0.1:5678");

    bool opt_enable_report = false;
    const char *lockname = 0;
    tcpdemux &demux = *tcpdemux::getInstance();
    feature_recorder::set_main_threadid();

    /* Set up debug system */
    init_debug(progname,1);

    /* Make sure that the system was compiled properly */
    if(sizeof(struct be13::ip4)!=20 || sizeof(struct be13::tcphdr)!=20){
        fprintf(stderr,"COMPILE ERROR.\n");
        fprintf(stderr,"  sizeof(struct ip)=%d; should be 20.\n", (int)sizeof(struct be13::ip4));
        fprintf(stderr,"  sizeof(struct tcphdr)=%d; should be 20.\n", (int)sizeof(struct be13::tcphdr));
        fprintf(stderr,"CANNOT CONTINUE\n");
        exit(1);
    }

    demux.opt.zmq_enabled = true;
    demux.opt.output_strip_nonprint = false;
    // demux.opt.max_bytes_per_flow = atoi(optarg);
    // demux.opt.suppress_header = 1;
    be13::plugin::scanners_disable_all();
    be13::plugin::scanners_enable("tcpdemux");
    demux.opt.store_output = true;  // must be true in order to process out-of-order packets etc.
    demux.opt.post_processing = true;   // we send the tcp content via zmq in post-process hook
    
    std::string outdir = "/ethernet-proxy";

    // ensure path exists and empty it before operation
    boost::filesystem::remove_all(outdir);
    boost::filesystem::create_directories(outdir);

    demux.outdir = outdir;
    flow::outdir = outdir;

    /* Load all the scanners and enable the ones we care about */
    scanner_info si;
    si.config = &be_config;
    si.get_config("enable_report",&opt_enable_report,"Enable report.xml");
    be13::plugin::load_scanners(scanners_builtin,be_config);
    be13::plugin::scanners_process_enable_disable_commands();

    /* was a semaphore provided for the lock? */
    if(lockname){
#if defined(HAVE_SEMAPHORE_H) && defined(HAVE_PTHREAD_H)
	semlock = sem_open(lockname,O_CREAT,0777,1); // get the semaphore
#else
	fprintf(stderr,"attempt to create lock pthreads not present\n");
	exit(1);
#endif
    }

    /* Debug prefix set? */
    std::string debug_prefix=progname;
    si.get_config("debug-prefix",&debug_prefix,"Prefix for debug output");
    init_debug(debug_prefix.c_str(),0);

    DEBUG(10) ("%s version %s ", PACKAGE_NAME, PACKAGE_VERSION); 

    //feature_file_names_t feature_file_names;
    //be13::plugin::get_scanner_feature_file_names(feature_file_names);

    si.get_config("tdelta",&datalink_tdelta,"Time offset for packets");
    si.get_config("packet-buffer-timeout", &packet_buffer_timeout, "Time in milliseconds between each callback from libpcap");

    feature_file_names_t feature_file_names;
    be13::plugin::get_scanner_feature_file_names(feature_file_names);
    feature_recorder_set fs(feature_recorder_set::NO_ALERT,be_hash,device.c_str(),demux.outdir);
    fs.init(feature_file_names);
    the_fs   = &fs;
    demux.fs = &fs;

	/* live capture */
    int exit_val = 0;

	demux.start_new_connections = true;
    int err = process_infile(demux, expression, device, "");
    if (err < 0) {
        exit_val = 1;
    }

    DEBUG(10) ("process_infile stopped with code: %d", err); 

    demux.remove_all_flows();	// empty the map to capture the state
    be13::plugin::phase_shutdown(*the_fs);

    exit(exit_val);
}

int main() {
    gg_error err = GGE_SUCCESS;

    err = gg_global_init(0);
    if(err) {
        gg_log(GG_LOG_ERROR, "gg_global_init failed %d", err);
        return -1;
    }

    gg_runtime_start(handler, GG_RT_OPT_ASYNC);

	const char* device = std::getenv("DEVICE");
	const char* expression = std::getenv("EXPRESSION");
    const std::string device_str(device);
    const std::string expression_str(expression);

    tcpflow(device_str, expression_str);

    return -1;
}


/* for debugging purposes:
int main() {
    const char* device = std::getenv("DEVICE");
	const char* expression = std::getenv("EXPRESSION");
    const std::string device_str(device);
    const std::string expression_str(expression);

    tcpflow(device_str, expression_str);
}
*/