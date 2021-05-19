const zmq = require("zeromq");
const msgpack = require('msgpack5')();

const sock = new zmq.Subscriber;

function bin2String(array) {
    var result = "";
    if (!array.slice(4, 16).some(a => a != 0)) {
        array = array.slice(0, 4);
    }

    for (var i = 0; i < array.length; i++) {
        if(i != 0) {
            result += "."
        }
        result += array[i]
    }

    return result;
}

(async function() {
    sock.connect("tcp://127.0.0.1:5678");
    sock.subscribe();
    console.log("Subscriber connected to port 5678");

    for await (const [msg] of sock) {
        const msg_decoded = msgpack.decode(msg);    
        console.log("data:" + msg_decoded.data);    // [...msg_decoded.data] to get the byte array
        console.log("src ip:" + bin2String(new Uint16Array(msg_decoded.src)));
        console.log("dst ip:" + bin2String(new Uint16Array(msg_decoded.dst)));
        console.log("src port:" + bin2String(new Uint16Array(msg_decoded.sport)));
        console.log("dst port:" + bin2String(new Uint16Array(msg_decoded.dport)));
    }
})();