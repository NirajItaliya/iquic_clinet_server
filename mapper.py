
from events import *
from events.Events import *
# s = Scapy()


def QuicInputMapper(alphabet, s):
    match alphabet:
        case "Clinet_Hello":
            x = s.send(SendInitialCHLOEvent())
        case "GET":
            x = s.send(SendGETRequestEvent())
        case "CLOSE":
            x = s.send(CloseConnectionEvent())
        case "Clinet_FIN":
            x = s.send(SendFINEvent())
        case "Server_Hello":
            x = s.send(SendServerHelloEvent())
        case "EE+CERT+CV+FIN":
            x = s.send(SendhandshakeEvent())
        case "Handshake_Done":
            x = s.send(SendhandshakedoneEvent())
        case "HTTP":
            x = s.send(SendHttpData())
        case default:
            pass
    return x


def QuicOutputMapper(data):
    output = ""
    if data == b"Server_Hello+Handshake+appliction_data":
        output = "Server_Hello+Handshake+appliction_data"
    elif data == b"push_promiseApplication_headerHTML" :
        output = "push_promise, Application_header, HTTP3 "
    elif data == b"ERROR":
        output = "ERROR"
    elif data == b"closed":
        output = "closed"
    elif data == b"html":
        output = "HTTP"
    elif data == b"HTML":
        output = "HTTP"
    elif data == b"EXP":
        output = "EXP"
    elif data == b'HD':
        output = "handshakedone"
    elif data == b'-':
        output = "-"
    elif data == b'Finish+GET':
        output = "FIN + GET"
    elif data == b'Error':
        output = "ERROR"
    else:
        output = "ERROR"
    return output