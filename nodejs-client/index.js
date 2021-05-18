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
        console.log("data:" + msg_decoded.data);
        console.log("src:" + bin2String(new Uint16Array(msg_decoded.src)));
        console.log("dst:" + bin2String(new Uint16Array(msg_decoded.dst)));
    }
})();