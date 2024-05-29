
import re
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary, hex_to_decimal,decrypte_length
import random
from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance
from crypto.Secret import dhke, Crypto
from CryptoFrame import CryptoFrame ,ACKFrame,ACKFrameModify,TLSFinish,CryptoFrameModify
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent,SendFINEvent

# from scapy.layers.tls.handshake import TLSFinished
from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed, retire_connection_id, quic_stream_0b,quic_stream_08
import os
import qpack 
from aioquic.quic.crypto import CryptoContext,CryptoPair
from  Keylog import KeyFile


# https://quic.aiortc.org:443
DPORT = 4433
# DPORT = 4433
ip ="localhost"


'''

vesrion 
29 -> 4278190109
28 -> 4278190108
'''

# DPORT = 443
# ip ="62.21.254.154"
class QUIC : 

    Largest_Acked = 0

    def __init__(self,s) -> None:

        self.crypto = Crypto()
        self.cryptoContext = CryptoContext()
        self.crypto_pair = CryptoPair()   
        self.datagrammaxsize = 1200
        self.chiper_suite = 0x1302
        self.version = 1
        self.handshake_packet_offset =25
        self.application_packet_offset =9
        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
        
        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)
        self.UDPClientSocket.connect((ip, DPORT))
        dhke.set_up_my_keys()
        self.UDPClientSocket.settimeout(.5)

    def reset(self, reset_server, reset_run=True):
        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.

            self.run = ""
            # set Destination conncetion id 
            destination_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
            SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
            
            # set source conncetion id 
            source_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

            # PacketNumberInstance.get_instance().reset()
            PacketNumberInstance.get_instance().reset()

            SessionInstance.get_instance().public_values_bytes = ""
            SessionInstance.get_instance().private_value = ""
            SessionInstance.get_instance().shared_key= b""
            SessionInstance.get_instance().server_handshake_traffic_secret = b"" 
            SessionInstance.get_instance().client_handshake_traffic_secret = b""
            SessionInstance.get_instance().server_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_handshake_secret = b""
            SessionInstance.get_instance().server_handshake_secret =b""
            SessionInstance.get_instance().handshake_done = False
            SessionInstance.get_instance().total_handshakepacket = 0
            dhke.set_up_my_keys()


    def initial_chlo(self, only_reset):

        self.reset(only_reset)

        packet_number = 0
        # client hello hanshake messages
        ClientHello =  bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().TLSObject("localhost").data))
        SessionInstance.get_instance().tlschlo = ClientHello

        # crypato Frame continent client hello hanshake messages  
        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(ClientHello).to_bytes(2, byteorder='big'))[1:]))
        crypto_frame =  bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        # here padding is added to make the packet size 1200: 18 --> is packet number + AEAD tag size, 26 --> is header size     
        padding = bytes.fromhex("00" * (self.datagrammaxsize - 18 - 26 - len(ClientHello) - len(crypto_frame)))  # padding
        plain_payload = crypto_frame + ClientHello + padding

        # Long Header
        chlo = QUICHeader.QUICHeader() 
        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        chlo.setfieldval("Length",bytes.fromhex("4" + bytes.hex((len(plain_payload) + 18).to_bytes(2, byteorder='big'))[1:]))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 
        print(bytes.hex(plain_header))
        #client initial packet encrypt using initial traffic secret
        self.crypto_pair.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,self.version) 
        data = self.crypto_pair.encrypt_packet(plain_header,plain_payload,packet_number)
      
        #send -> Initial[0] : crypato(CH)
        self.UDPClientSocket.send(data)
        pattern = b""
        try :
        
            # receive -> Initial[0] : crypato(SH)
            datarev_1 = self.UDPClientSocket.recv(1300)
            # only Receive Initial packet
            while hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] != "00" :
                datarev_1 = self.UDPClientSocket.recv(1300) 
                if(hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] == "00") : break 

            packet_length = decrypte_length(datarev_1[24:26])
            server_initial = datarev_1[:26+packet_length] #Initial[0] : crypato(SH)
        
            #server initial packet decrypat using initial traffic secret
            plain_header, temo_payload, packet_number = self.crypto_pair.decrypt_packet(server_initial,self.handshake_packet_offset+1,0)
            self.send_initial_ACK(packet_number)
            PacketNumberInstance.get_instance().highest_received_packet_number = packet_number

            payload = temo_payload[:100]
            sever_public_key = payload[-32:]
            dhke.shared_key_computation(sever_public_key)
            server_hello_data = payload[10:]
            SessionInstance.get_instance().tlsshalo = server_hello_data
            self.chiper_suite =  int.from_bytes((server_hello_data[39:41]), byteorder='big')
            DCID = plain_header[6:14]
            SCID = plain_header[15:23]
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            dhke.handshake_traffic_computation()
            pattern += b"Server_Hello"


            handshake_packet_data = datarev_1[26+packet_length:]
            if handshake_packet_data != b'':
                SessionInstance.get_instance().total_handshakepacket += 1
                self.cryptoContext.setup(cipher_suite = self.chiper_suite, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = self.version)
                plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(handshake_packet_data,self.handshake_packet_offset,1)
                PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
                extensions_legth = hex_to_decimal(bytes.hex(payload[5:8]))
                SessionInstance.get_instance().crypto_extensions = payload[4:extensions_legth+8] # EE

                Certifacte_legth = hex_to_decimal(bytes.hex(payload[extensions_legth+9:extensions_legth+12]))
                SessionInstance.get_instance().crypto_cert = payload[extensions_legth+8:] # CERT
                padding_legth = Certifacte_legth + 4  - len(SessionInstance.get_instance().crypto_cert)
        except :  
            print("initial packet Not receive")
            return b"EXP"

        try :
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
            data_recv = self.UDPClientSocket.recv(1300)
            if SessionInstance.get_instance().total_handshakepacket == 1 :
                packet_length = decrypte_length(data_recv[23:25])
                handshake_packet = data_recv[:25+packet_length]
                application_data = data_recv[25+packet_length:]

                SessionInstance.get_instance().total_handshakepacket += 1
                self.cryptoContext.setup(cipher_suite =self.chiper_suite, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = self.version)
                plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(handshake_packet,self.handshake_packet_offset,1)
                PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)

                SessionInstance.get_instance().crypto_cert +=   payload[5:padding_legth + 5]
                CV_legth = hex_to_decimal(bytes.hex(payload[padding_legth+6:padding_legth + 9])) 
                SessionInstance.get_instance().crypto_certverify = payload[padding_legth +5 : padding_legth + 9 + CV_legth]                
                finish_legth = hex_to_decimal(bytes.hex(payload[padding_legth + 9 + CV_legth + 1 :padding_legth + 9 + CV_legth + 4]))
                SessionInstance.get_instance().crypto_finished = payload[padding_legth + 9 + CV_legth:]                 
                pattern += b"+Handshake"
                dhke.appliction_traffic_computation()

                self.cryptoContext.setup(cipher_suite = self.chiper_suite, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = self.version)
                plain_header, payload, packet_number,crypto =  self.cryptoContext.decrypt_packet(application_data,self.application_packet_offset,0)
                PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
                pattern += b"+appliction_data"
                return pattern
            else : 
                '''
                Here handshake packet is in fragmentation  
                '''
                self.cryptoContext.setup(cipher_suite = self.chiper_suite, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = self.version)
                plain_header_sp, payload_sp, packet_number_sp,crypto = self.cryptoContext.decrypt_packet(data_recv,self.handshake_packet_offset,1)

                PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_sp)

                SessionInstance.get_instance().crypto_extensions = payload_sp[4:114]                    # EE
                SessionInstance.get_instance().crypto_cert = payload_sp[114:]                         # CERT

        except:
            print("handshake Packet 1 not receive")
            return b"EXP"
        
        
        try :
            # receive -> 1-RTT[0] : appliction_data
            data = self.UDPClientSocket.recv(1300) 
            handshake_data_2 = data[:987]
            appliction_data = data[987:]

            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = self.version)
            plain_header_tp, payload_tp, packet_number_tp,crypto = self.cryptoContext.decrypt_packet(handshake_data_2,self.handshake_packet_offset,1)

            SessionInstance.get_instance().crypto_cert += payload_tp[5:500]
            SessionInstance.get_instance().crypto_certverify = payload_tp[500:892]
            SessionInstance.get_instance().crypto_finished = payload_tp[892:]
            pattern += b"+Handshake"

            dhke.appliction_traffic_computation()
            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = self.version)
            plain_header_ap, payload_ap, packet_number_ap,crypto =  self.cryptoContext.decrypt_packet(appliction_data,self.application_packet_offset,0)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            pattern += b"+appliction_data"
            # self.send_handshake()
            # self.send_ACK_applictiondata()
        except:
            print("appliction Packet 2  not receive")
            return b"EXP"
        
        return pattern
    

    def send_initial_ACK(self,packet_number = 0):

        #initial ACK packet        
         #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",packet_number)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("4059"))
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        
        initial_clinet_ACK = bytes.fromhex(ACK_frame)

        padding = bytes.fromhex("00" * (self.datagrammaxsize - 18 - 26 - len(ACK_frame))) 
        plain_payload = initial_clinet_ACK + padding
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()
        _packet_number = PacketNumberInstance.get_instance().get_next_packet_number()

        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4" + bytes.hex((len(plain_payload) + 18).to_bytes(2, byteorder='big'))[1:]))
        initial_client_ACK_header.setfieldval("Packet_Number",256 * _packet_number)
        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
       
        #Initial ACK packet encrypt using initial traffic secret
       # initial_clinet_data = self.crypto.encrypt_initial_packet(initial_header,initial_clinet_ACK,_packet_number)
        self.crypto_pair.setup_initial(string_to_ascii(SessionInstance.get_instance().client_initial_destination_connection_id ),True,self.version)
        data = self.crypto_pair.encrypt_packet(initial_header,initial_clinet_ACK,_packet_number)
        self.UDPClientSocket.send(data)
        
    
    def send_handshake(self) :
        # Long Header
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4016"))
        handshake_client_ACK_header.setfieldval("Packet_Number",256* PacketNumberInstance.get_instance().get_next_packet_number())

         #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("407e"))
        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))

        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("407e"))
        handshake_clinet_ACK1 = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))
        
        handshake_client_data = self.crypto.encrypt_handshake_packet(bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header)),handshake_clinet_ACK + handshake_clinet_ACK1)
        self.UDPClientSocket.send(handshake_client_data)

    
    def send_finish(self):

        if SessionInstance.get_instance().handshake_done == True : return b"ERROR" 
        handshake_client_finish_header = QUICHeader.QUICHandshakeHeader()
        # set header data
        handshake_client_finish_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_finish_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_finish_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_finish_header.setfieldval("Length",bytes.fromhex("4050"))
        handshake_client_finish_header.setfieldval("Packet_Number",256 * PacketNumberInstance.get_instance().get_next_packet_number())
        _handshake_client_ACK_header =  bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_finish_header))

        #ack frame
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("40de"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame = extract_from_packet_as_bytestring(ackFrame_handshake)

        #crypto frame for finish 
        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("4034"))
        _crypatoFrame = extract_from_packet_as_bytestring(cryptoFrame)

        finished_verify_data = dhke.finished_verify_data(0x1302,SessionInstance.get_instance().client_handshake_traffic_secret)
        #finsh message 
        tlsfinsh = TLSFinish()
        tlsfinsh.setfieldval("vdata",bytes.fromhex(bytes.hex(finished_verify_data)))
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
    
        handshake_clinet_data =self.crypto.encrypt_handshake_packet(_handshake_client_ACK_header,data)

        # 1 - RTT packet 
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        _new_connection_id_data = b""
        
        for i in range(1,8) :
            new_connection_id_data = new_connection_id()
            new_connection_id_data.setfieldval("Sequence" ,i)
            new_connection_id_data.setfieldval("CID" ,os.urandom(8))
            new_connection_id_data.setfieldval("Stateless_Reset_Token" ,os.urandom(16))
            _new_connection_id_data +=  bytes.fromhex(extract_from_packet_as_bytestring(new_connection_id_data))


        stream_data = bytes.fromhex("0004090150000710080121010d0108")
        stream_1 = quic_stream()
        stream_1.setfieldval("stream_id",2)
        stream_1.setfieldval("Length",bytes.fromhex("400f"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))
        
        stream_2 = quic_stream()
        stream_2.setfieldval("stream_id",6)
        stream_2.setfieldval("Length",bytes.fromhex("4001"))
        stream_2.setfieldval("Data",bytes.fromhex("02"))
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        stream_3 = quic_stream()
        stream_3.setfieldval("stream_id",10)
        stream_3.setfieldval("Length",bytes.fromhex("4001"))
        stream_3.setfieldval("Data",bytes.fromhex("03"))
        _stream_3 = bytes.fromhex(extract_from_packet_as_bytestring(stream_3))

        data = _new_connection_id_data + _stream_1 + _stream_2 + _stream_3
        self.send_ACK_applictiondata()

        #encrypation using ap traffic secret

        appliction_clinet_data =  self.crypto.encrypt_application_packet(_haeader,data)
        self.UDPClientSocket.send(handshake_clinet_data + appliction_clinet_data)
        try :
            #1 - RTT[1]: [HD, Application Data]        
            recv_handshake_done = self.UDPClientSocket.recv(1200) # recive frist packet 4
            recv_ACK_ = self.UDPClientSocket.recv(100) # recive ACK packet 6
            self.cryptoContext.setup(cipher_suite = self.chiper_suite,secret =  SessionInstance.get_instance().server_appliction_traffic_secret  ,version = self.version)
            plain_header, payload, packet_number, crypto = self.cryptoContext.decrypt_packet(recv_handshake_done,self.application_packet_offset,0)  
            
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
            
            handshake_done = payload[6:7]
            if(extract_from_packet_as_bytestring(handshake_done) == "1E") :
                print("handshake done")
            
            SessionInstance.get_instance().handshake_done = True
            self.send_ACK_applictiondata()
            self.send_ack_for_message()
            
            return b"HD"

        except : 
            print("packet Not receive")
            return b"EXP"
        

    def send_ACK_applictiondata(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #ack frame
        ackFrame_appliction = ACKFrame()
        ackFrame_appliction.setfieldval("Largest_Acknowledged",3)
        ackFrame_appliction.setfieldval("ACK_delay",bytes.fromhex("4194"))
        ackFrame_appliction.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_appliction))
        appliction_clinet_data =  self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        self.UDPClientSocket.send(appliction_clinet_data)
        
    
    def Send_application_header(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        stream_data_2 = bytes.fromhex("3fe11f")
        stream_2 = quic_offset_stream()
        stream_2.setfieldval("stream_id",6)
        stream_2.setfieldval("offset",1)
        stream_2.setfieldval("Length",bytes.fromhex("4003"))
        stream_2.setfieldval("Data",stream_data_2)
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        stream_data = bytes.fromhex("011e0000d1d7508aa0e41d139d09b8d34cb3c15f508a198fdad311802efae26f")
        stream_1 = quic_stream()
        stream_1.setfieldval("Frame_Type",0x0b)
        stream_1.setfieldval("stream_id",0)
        stream_1.setfieldval("Length",bytes.fromhex("4020"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

        data =  _stream_2 +_stream_1
        
        appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,data)
        self.UDPClientSocket.send(appliction_clinet_data)

        # try :
        #     push_promise = self.UDPClientSocket.recv(1000)
        #     plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(push_promise)
        # except :
        #     pass
        
        # try :
        #     Application_header = self.UDPClientSocket.recv(1000) 
        #     plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(Application_header)
        # except :
        #     pass
        
        # try :
        #     Application_header = self.UDPClientSocket.recv(1000) 
        #     plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(Application_header)
        # except :
        #     pass
        
        pattern = b""
        try :
            html_page_1 = self.UDPClientSocket.recv(1300) 

            while len(html_page_1) < 1000:
                html_page_1 = self.UDPClientSocket.recv(1300) 
                
            self.cryptoContext.setup(cipher_suite = self.chiper_suite,secret =  SessionInstance.get_instance().server_appliction_traffic_secret  ,version = self.version)
            plain_header, payload_ap, packet_number_ap, crypto = self.cryptoContext.decrypt_packet(html_page_1,self.application_packet_offset,0)  
            # print(payload_ap)
            # print(bytes.hex(payload_ap))
            pattern_match = re.search(b"html", payload_ap)
            if pattern_match:
                pattern += b"html"
            else :
                return b"EXP"
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
        except : 
            print(" HTML Page 1 packet Not receive")
            return b"EXP"

        try :
            html_page_2 = self.UDPClientSocket.recv(1300) 
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(html_page_2)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            self.send_ack_for_message_6()

        except : 
            print("HTML Page 2 packet Not receive")
            # return b"EXP"
        
        return pattern
        
    def send_ack_for_message(self):

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",PacketNumberInstance.get_instance().get_highest_received_packet_number())
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

        try : 
            appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        except:
            return b"EXP"
        
        self.UDPClientSocket.send(appliction_clinet_data)

       
    def send_ack_for_message_6(self):

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",6)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

        try :
            appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        except:
            return b"EXP"
        
        self.UDPClientSocket.send(appliction_clinet_data)
        
        try :
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto.decrypt_application_packet(push_promise)
        except :
            return b"EXP" 
    
    def connection_close(self) :
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #connection_closed
        connection_clodsed = quic_connection_closed()
        _connection_clodsed=  bytes.fromhex(extract_from_packet_as_bytestring(connection_clodsed))
        if SessionInstance.get_instance().handshake_done == False :
            return b"EXP" 
        try :
            connection_close_data = self.crypto.encrypt_application_packet(_haeader,_connection_clodsed)
            self.UDPClientSocket.send(connection_close_data)
            return b"closed"
        except :
            return b"EXP" 
        
    def send(self, command):
        try:
            if isinstance(command, SendInitialCHLOEvent):
                print("Sending InitialCHLO")
                return self.initial_chlo(True)
            elif isinstance(command, SendFINEvent):
                print("Sending FIN")
                return self.send_finish()
            elif isinstance(command, SendGETRequestEvent):
                print("Sending GET")
                return self.Send_application_header()
            elif isinstance(command, CloseConnectionEvent):
                print("Closing connection")
                return self.connection_close()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            print("error")


from aioquic.quic.crypto import CryptoContext,CryptoPair

class QUIC_GO : 

    Largest_Acked = 0

    def __init__(self,s) -> None:

        self.crypto = Crypto()
        self.cryptoContext = CryptoContext()
        self.cryptopair = CryptoPair()  
        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
        
        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)
        self.UDPClientSocket.connect(("127.0.0.1", 6121))
        dhke.set_up_my_keys()
        self.UDPClientSocket.settimeout(.5)

    def reset(self, reset_server, reset_run=True):
        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.

            self.run = ""
            # set Destination conncetion id 
            destination_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
            SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
            
            # set source conncetion id 
            source_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

            # PacketNumberInstance.get_instance().reset()
            PacketNumberInstance.get_instance().reset()

            SessionInstance.get_instance().public_values_bytes = ""
            SessionInstance.get_instance().private_value = ""
            SessionInstance.get_instance().shared_key= b""
            SessionInstance.get_instance().server_handshake_traffic_secret = b"" 
            SessionInstance.get_instance().client_handshake_traffic_secret = b""
            SessionInstance.get_instance().server_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_handshake_secret = b""
            SessionInstance.get_instance().server_handshake_secret =b""
            SessionInstance.get_instance().handshake_done = False
            dhke.set_up_my_keys()


    def initial_chlo(self, only_reset):

        self.reset(only_reset)

        # Long Header
        chlo = QUICHeader.QUICHeader() 

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 

        # crypato Frame continent client hello hanshake messages  
        cryptoFrame = CryptoFrame() 
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        ClientHello = bytes.hex(CryptoFrame().TLSObject("localhost").data)
        SessionInstance.get_instance().tlschlo = bytes.fromhex(ClientHello)
        # padding
        padding = "00" * (775)
        
        # client hello hanshake messages + padding
        plain_payload = bytes.fromhex(crypto_frame + ClientHello + padding)

        #client initial packet encrypt using initial traffic secret
        data =self.crypto.encrypt_initial_packet(plain_header,plain_payload,0)
      
        #send -> Initial[0] : crypato(CH)
        self.UDPClientSocket.send(data)
        pattern = b""
        extenstion_len = 0
        try :
           
            # receive -> Initial[0] : crypato(SH)
            datarev_1 = self.UDPClientSocket.recv(1400) 

            # only Receive Initial packet
            while SessionInstance.get_instance().initial_source_connection_id != bytes.hex(datarev_1[6:14]):
                datarev_1 = self.UDPClientSocket.recv(1400) 

               
            server_initial = datarev_1[:139]  #Initial[0] : crypato(SH)
            server_handshake_1 = datarev_1[139:] #handshake[0] : crypato(EE)

            
            #server initial packet decrypat using initial traffic secret
            self.cryptopair.setup_initial(bytes.fromhex(SessionInstance.get_instance().client_initial_destination_connection_id), True, 1)
            plain_header, payload, packet_number = self.cryptopair.decrypt_packet(server_initial,22,0)

            sever_public_key = payload[-32:]
            server_hello_data = payload[9:]
            SCID = plain_header[15:19]
        
            PacketNumberInstance.get_instance().highest_received_packet_number = packet_number
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            SessionInstance.get_instance().tlsshalo = server_hello_data
            
            dhke.shared_key_computation(sever_public_key)
            dhke.handshake_traffic_computation(_cipher_suite = 0x1301)
            # handshake packet decrypation 
            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_handshake_traffic_secret,version=1)  
            plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(server_handshake_1,21,0)

            extenstion_len = int.from_bytes(payload[5:8], byteorder='big') + 4 # get all extenstion messges, heare we have only EE
            SessionInstance.get_instance().crypto_extensions = payload[4:4 + extenstion_len]            
            SessionInstance.get_instance().crypto_cert = payload[4 + extenstion_len :extenstion_len + 746]   
            SessionInstance.get_instance().crypto_certverify = payload[extenstion_len + 746:]
            PacketNumberInstance.get_instance().highest_received_packet_number = packet_number
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)    
            pattern += b"Server_Hello"
        

        except :  
            print("initial packet Not receive")
            return b"EXP"

        try :
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
        
            packet = self.UDPClientSocket.recv(1300)
            handshake_packet = packet[:extenstion_len + 16]
            appliction_data = packet[extenstion_len + 16:]

            plain_header_sp, payload_sp, packet_number_sp, crypto  =  self.cryptoContext.decrypt_packet(handshake_packet,21,0)

            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_sp)
            SessionInstance.get_instance().crypto_certverify += payload_sp[:-36][5:]   # CV       
            SessionInstance.get_instance().crypto_finished = payload_sp[-36:]     # FIN   
            
            pattern += b"+Handshake"
            dhke.appliction_traffic_computation(_cipher_suite = 0x1301)
            KeyFile.FileGenret()
            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_appliction_traffic_secret,version=1)
            plain_header_ap, payload_ap, packet_number_ap, crypto  =   self.cryptoContext.decrypt_packet(appliction_data,9,0)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            pattern += b"+appliction_data"
            self.send_ACK()
        except:
            print("handshake 1 Packet not receive")
            return b"EXP"
        
        try :
            packet = self.UDPClientSocket.recv(1300)
            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_appliction_traffic_secret,version=1)
            plain_header_ap, payload_ap, packet_number_ap, crypto  =   self.cryptoContext.decrypt_packet(appliction_data,9,0)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            # pattern += b"appliction_data"
        except:
            print("handshake Packet not receive")
            return b"EXP"

        
        return pattern

    def send_ACK(self):

         #initial ACK packet        
     
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()
        # set destination and source id in header
        
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID_Length",4)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID_Length",8)
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("44d2"))
        initial_client_ACK_header.setfieldval("Packet_Number",256 * PacketNumberInstance.get_instance().get_next_packet_number())
        padding = "00" * (1211)    

        #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrameModify()
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("00"))
        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        initial_clinet_ACK = bytes.fromhex(ACK_frame + padding)

        #Initial ACK packet encrypt using initial traffic secret
        self.cryptopair.setup_initial(bytes.fromhex(SessionInstance.get_instance().client_initial_destination_connection_id), True, 1)
        data = self.cryptopair.encrypt_packet(initial_header,initial_clinet_ACK, 1)
        self.UDPClientSocket.send(data)
    

    def send_finish(self):

        if SessionInstance.get_instance().handshake_done == True : return b"ERROR" 
        handshake_client_finish_header = QUICHeader.QUICHandshakeHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        # set header data
        handshake_client_finish_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_finish_header.setfieldval("DCID_Length",4)
        handshake_client_finish_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_finish_header.setfieldval("SCID_Length",8)
        handshake_client_finish_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_finish_header.setfieldval("Length",bytes.fromhex("403e"))
        handshake_client_finish_header.setfieldval("Packet_Number",256 * packet_number)
        _handshake_client_ACK_header =  bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_finish_header))

       #ack frame
        ackFrame_handshake = ACKFrameModify()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("00"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame = extract_from_packet_as_bytestring(ackFrame_handshake)

        #crypto frame for finish 
        cryptoFrame = CryptoFrameModify() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("24"))
        _crypatoFrame = extract_from_packet_as_bytestring(cryptoFrame)

        finished_verify_data = dhke.finished_verify_data(0x1301,SessionInstance.get_instance().client_handshake_traffic_secret)

        #finsh message 
        tlsfinsh = TLSFinish()
        tlsfinsh.setfieldval("Length",bytes.fromhex("000020"))
        tlsfinsh.setfieldval("vdata",bytes.fromhex(bytes.hex(finished_verify_data)))
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
        self.cryptoContext.setup(cipher_suite=0x1301,secret= SessionInstance.get_instance().client_handshake_traffic_secret,version=1)
        handshake_clinet_data =self.cryptoContext.encrypt_packet(_handshake_client_ACK_header,data,packet_number)

        self.UDPClientSocket.send(handshake_clinet_data)
  
        pattern = b""
        try :
            #1 - RTT[1]: [HD, Application Data]        
            recv_handshake_done = self.UDPClientSocket.recv(1300) 

            while SessionInstance.get_instance().initial_source_connection_id != bytes.hex(recv_handshake_done[1:9]):
                recv_handshake_done = self.UDPClientSocket.recv(1400) 


            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_appliction_traffic_secret,version=1)   
            plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(recv_handshake_done,9,1)
            
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
            pattern_match= payload.find(b"1E")
            if(pattern_match):
                print("handshake done")
                pattern += b"HD"
            
            SessionInstance.get_instance().handshake_done = True
            self.send_fin_ack()
            recv_handshake_done = self.UDPClientSocket.recv(1200)
            self.send_fin_ack_4()
            return pattern
        except : 
            print("packet done Not receive")
            return b"EXP"
        

        
    def send_fin_ack(self):
        
        haeader = QUICHeader.QUICGoShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",2)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

       
        self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().client_appliction_traffic_secret,version=1)   
        appliction_clinet_data =  self.cryptoContext.encrypt_packet(_haeader,_ackFrame,packet_number)

        self.UDPClientSocket.send(appliction_clinet_data)

    def send_fin_ack_4(self):
        
        haeader = QUICHeader.QUICGoShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",3)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

       
        self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().client_appliction_traffic_secret,version=1)   
        appliction_clinet_data =  self.cryptoContext.encrypt_packet(_haeader,_ackFrame,packet_number)

        self.UDPClientSocket.send(appliction_clinet_data)
    
    def send_fin_ack_5(self):
        
        haeader = QUICHeader.QUICGoShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",5)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

       
        self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().client_appliction_traffic_secret,version=1)   
        appliction_clinet_data =  self.cryptoContext.encrypt_packet(_haeader,_ackFrame,packet_number)

        self.UDPClientSocket.send(appliction_clinet_data)

    def Send_application_header(self):
        haeader = QUICHeader.QUICGoShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))


        stream_data = bytes.fromhex("01250000508aa0e41d139d09b8e0441fd1c1d75f10839bd9ab5f508bed6988b4c7531efdfad867")
        stream_1 = quic_stream_0b()
        stream_1.setfieldval("stream_id",0)
        stream_1.setfieldval("Length",bytes.fromhex("27"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))
        
        stream_2 = quic_stream_08()
        stream_2.setfieldval("stream_id",2)
        stream_2.setfieldval("Data",bytes.fromhex("000400"))
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        data =   _stream_1 + _stream_2
          
        self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().client_appliction_traffic_secret,version=1)   
        appliction_clinet_data =  self.cryptoContext.encrypt_packet(_haeader,data,packet_number)
        self.UDPClientSocket.send(appliction_clinet_data)
        
        pattern = b""
        try :
            html_page_1 = self.UDPClientSocket.recv(1300) 
            html_page_1 = self.UDPClientSocket.recv(1300) 
            while SessionInstance.get_instance().initial_source_connection_id != bytes.hex(html_page_1[1:9]):
                html_page_1 = self.UDPClientSocket.recv(1400) 
           

            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_appliction_traffic_secret,version=1)   
            plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(html_page_1,9,1)
            pattern_match = re.search(b"html", payload)
            if pattern_match:
                pattern += b"html"
            else :
                return b"EXP"
            self.send_fin_ack_5()   
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
        except : 
            print(" HTML Page 1 packet Not receive")
            return b"EXP"
        
        # try :
        #     html_page_1 = self.UDPClientSocket.recv(1300) 
        #     self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().server_appliction_traffic_secret,version=1)   
        #     plain_header, payload, packet_number,crypto = self.cryptoContext.decrypt_packet(html_page_1,9,1)
        # except : 
        #     print(" HTML Page 1 packet Not receive")
        #     return b"EXP"
        
        return pattern

    def connection_close(self) :
        haeader = QUICHeader.QUICGoShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))
        #connection_closed
        connection_clodsed = quic_connection_closed()
        _connection_clodsed=  bytes.fromhex(extract_from_packet_as_bytestring(connection_clodsed))
        if SessionInstance.get_instance().handshake_done == False :
            return b"EXP" 
        try :
            self.cryptoContext.setup(cipher_suite = 0x1301,secret= SessionInstance.get_instance().client_appliction_traffic_secret,version=1)   
            connection_close_data = self.cryptoContext.encrypt_packet(_haeader,_connection_clodsed,packet_number)
            self.UDPClientSocket.send(connection_close_data)
            return b"closed"
        except :
            return b"EXP" 
        
    def send(self, command):
        try:
            if isinstance(command, SendInitialCHLOEvent):
                print("Sending InitialCHLO")
                return self.initial_chlo(True)
            elif isinstance(command, SendFINEvent):
                print("Sending FIN")
                return self.send_finish()
            elif isinstance(command, SendGETRequestEvent):
                print("Sending GET")
                return self.Send_application_header()
            elif isinstance(command, CloseConnectionEvent):
                print("Closing connection")
                return self.connection_close()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            print("error")    



# s = QUIC("localhost")

# print(s.initial_chlo(True))
# KeyFile.FileGenret()
# print(s.send_finish())
# print(s.Send_application_header())
# print(s.connection_close())


# s = QUIC_GO("localhost")

# print(s.initial_chlo(True))
# KeyFile.FileGenret()
# print(s.send_finish())
# print(s.Send_application_header())
# print(s.connection_close())


aioquic =  QUIC("localhost")
print(aioquic.initial_chlo(True))
KeyFile.FileGenret()
print(aioquic.Send_application_header())
print(aioquic.send_finish())
print(aioquic.Send_application_header())
print(aioquic.connection_close())
quic_go = QUIC_GO("localhost")


# print("----------------aioquic---------------------------------")
# if aioquic.initial_chlo(True) == b'Server_Hello+Handshake+appliction_data' :
#     print(b'Server_Hello+Handshake+appliction_data')
#     KeyFile.FileGenret()
#     print(aioquic.send_finish())
#     print(aioquic.Send_application_header())
#     print(aioquic.connection_close())
# else : print("ERROR: Server off")

# print("----------------quic-go---------------------------------")
# if quic_go.initial_chlo(True) == b'Server_Hello+Handshake+appliction_data' :
#     print(b'Server_Hello+Handshake+appliction_data')
#     KeyFile.FileGenret()
#     print(quic_go.send_finish())
#     print(quic_go.Send_application_header())
#     print(quic_go.connection_close())
# else : print("ERROR: Server off")