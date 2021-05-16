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

#include <string>
#include <vector>
#include <sys/types.h>

int packet_buffer_timeout = 10;

scanner_info::scanner_config be_config; // system configuration

const char *progname = "tcpflow-gg";
int debug = DEFAULT_DEBUG_LEVEL;

/* semaphore prevents multiple copies from outputing on top of each other */
#ifdef HAVE_PTHREAD_H
#include <semaphore.h>
sem_t *semlock = 0;
#endif

scanner_t *scanners_builtin[] = { scan_tcpdemux, 0};

bool opt_no_promisc = false;		// true if we should not use promiscious mode

/* These must be global variables so they are available in the signal handler */
//feature_recorder_set *the_fs = 0;
pcap_t *pd = 0;
void terminate(int sig) 
{
    if (sig == SIGHUP || sig == SIGINT || sig == SIGTERM) {
        DEBUG(1) ("terminating orderly");
        pcap_breakloop(pd);
        return;
    } else {
        DEBUG(1) ("terminating");
        // be13::plugin::phase_shutdown(*the_fs);	// give plugins a chance to do a clean shutdown
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


int main(int argc, char *argv[])
{
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
    std::string device = std::string("lo"); 
    demux.opt.store_output = false;
    demux.opt.post_processing = false;

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
	fprintf(stderr,"%s: attempt to create lock pthreads not present\n",argv[0]);
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

	/* live capture */
    int exit_val = 0;

	demux.start_new_connections = true;
    int err = process_infile(demux,"port 19000",device,"");
    if (err < 0) {
        exit_val = 1;
    }

    demux.remove_all_flows();	// empty the map to capture the state
    // be13::plugin::phase_shutdown(*the_fs);

    exit(exit_val);
}
