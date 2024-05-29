import socket
from aioquic.quic.crypto import CryptoContext,CryptoPair

import subprocess
import re
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary
import random
from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance
from crypto.Secret import dhke, Crypto
from CryptoFrame import CryptoFrame ,ACKFrame,ACKFrameModify,TLSFinish,CryptoFrameModify,CryptoFrameOffsetModify
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent,SendFINEvent

# from scapy.layers.tls.handshake import TLSFinished
from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed, retire_connection_id, quic_stream_0b,quic_stream_08
import os
import qpack 
from aioquic.quic.crypto import CryptoContext,CryptoPair
from  Keylog import KeyFile


# Replace 'script_to_run.py' with the name of the script you want to run
script_path = 'Client.py'


class iquic_server :
    def __init__(self,s) -> None:
        self.cryptoContext = CryptoContext()
        self.crypto_pair = CryptoPair() 
        self.UDPClientSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.ip = "localhost"
        self.port = 5050
        self.address = None
        self.UDPClientSocket.bind((self.ip, self.port))

    def reset(self, reset_server, reset_run=True):
        if reset_run:
            # set source conncetion id 
            source_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))
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
    
    def server_hello(self,only_reset):
        self.reset(only_reset)
        try :
            datarev_1,self.address = self.UDPClientSocket.recvfrom(1300)
            DCID = datarev_1[6:14]
            SessionInstance.get_instance().client_initial_destination_connection_id= bytes.hex(DCID)
            SCID = datarev_1[15:15+8]
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            self.crypto_pair.setup_initial(cid = DCID, is_client = False, version = 0x1)
            plain_header, pain_payload, packet_number = self.crypto_pair.decrypt_packet(datarev_1, 26, 0)
            clinet_public_key = pain_payload[134:134+32]
            SessionInstance.get_instance().randome_value = pain_payload[10:10+32]
            SessionInstance.get_instance().tlschlo = pain_payload[4:377+4]
        except Exception as e:
            print(e)
            print("not recived clinet hello packet")


        # Long Header
        chlo = QUICHeader.QUICHeader()

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(chlo))     

        aCKFrame = ACKFrame()
        aCKFrame.setfieldval("ACK_delay", bytes.fromhex("41b2")) 
        aCKFrame.setfieldval("Largest_Acknowledged",0)
        _ackFrame = bytes.fromhex(extract_from_packet_as_bytestring(aCKFrame))

        
        cryptoFrame = CryptoFrame()
        cryptoFrame.setfieldval("Length",bytes.fromhex("405a"))
        crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        ServerHello = bytes.hex(CryptoFrame().TLSObject_ServerHello().data)
        SessionInstance.get_instance().tlsshalo = bytes.fromhex(ServerHello)
        # print(bytes.hex(SessionInstance.get_instance().tlsshalo))
        dhke.shared_key_computation(server_public_key = clinet_public_key)
        dhke.handshake_traffic_computation() 
        KeyFile.FileGenret()
        padding = bytes.fromhex("00"*1056)
        pain_payload = _ackFrame + crypto_frame + bytes.fromhex(ServerHello) + padding 
        data = self.crypto_pair.encrypt_packet(plain_header, pain_payload, 0)
        self.UDPClientSocket.sendto(data,self.address)
        


    def Encrypted_Extensions(self) :
        packetNumber = PacketNumberInstance.get_instance().get_next_packet_number()

        _encryptedExtensions = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().get_EncryptedExtensions().data))
        SessionInstance.get_instance().crypto_extensions = _encryptedExtensions

        main_certificate =  bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().get_Certificate().data))
        SessionInstance.get_instance().crypto_cert = main_certificate
        certificate_part1 = main_certificate[:1043]    

        cryptoFrame = CryptoFrame()
        cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(_encryptedExtensions + certificate_part1).to_bytes(2, byteorder='big'))[1:]))
        crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        pain_payload = crypto_frame + _encryptedExtensions + certificate_part1

        # Long Header
        EEheder = QUICHeader.QUICHandshakeHeader()
        EEheder.setfieldval("Public_Flags", 0xe1)
        EEheder.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id))
        EEheder.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        EEheder.setfieldval("Packet_Number", packetNumber * 256 )
        EEheder.setfieldval("Length", bytes.fromhex("4" + bytes.hex((len(pain_payload) + 18).to_bytes(2, byteorder='big'))[1:]))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(EEheder))

        # padding = bytes.fromhex("00"*(1043))
       
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
        data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packetNumber)
        self.UDPClientSocket.sendto(data,self.address)

        packetNumber = PacketNumberInstance.get_instance().get_next_packet_number()
        certificate = main_certificate[1043:]

        certificate_verify = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().get_CertificateVerify().data))
        SessionInstance.get_instance().crypto_certverify = certificate_verify
        finish_messges = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().get_finish().data))
        SessionInstance.get_instance().crypto_finished = finish_messges


        cryptoFrame = CryptoFrameOffsetModify()
        cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(certificate + certificate_verify + finish_messges).to_bytes(2, byteorder='big'))[1:]))
        cryptoFrame.setfieldval("Offset",bytes.fromhex("4" + bytes.hex(len(certificate_part1 + _encryptedExtensions).to_bytes(2, byteorder='big'))[1:]))
        crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        pain_payload = crypto_frame + certificate +certificate_verify + finish_messges
        padding = bytes.fromhex("00"*(1175 - len(pain_payload) - 16 - 2))
        padding =  bytes.fromhex("")
        
        # Long Header
        CERTheader = QUICHeader.QUICHandshakeHeader()
        CERTheader.setfieldval("Public_Flags", 0xe1)
        CERTheader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id))
        CERTheader.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        CERTheader.setfieldval("Packet_Number", packetNumber * 256 )
        CERTheader.setfieldval("Length", bytes.fromhex("4" + bytes.hex((len(pain_payload + padding) + 18).to_bytes(2, byteorder='big'))[1:]))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(CERTheader))
        
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
        handshake_data = self.cryptoContext.encrypt_packet(plain_header, pain_payload  + padding , packetNumber)
        self.UDPClientSocket.sendto(handshake_data ,self.address)

        # dhke.appliction_traffic_computation()
        
        # #application data 
        # packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        # header = QUICHeader.QUICShortHeader()
        # header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id))
        # header.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        # plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(header))

        # new_session_tikict = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().new_session_ticket().data))
        # cryptoFrame = CryptoFrame()
        # cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(new_session_tikict).to_bytes(2, byteorder='big'))[1:]))
        # crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        # strem_data = bytes.fromhex("0004100150000710080121013301ab60374201")
        # quic_stream_1 = quic_stream()
        # quic_stream_1.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        # quic_stream_1.setfieldval("Data",strem_data)
        # quic_stream_1.setfieldval("stream_id", 3)
        # quic_stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_1))

        # strem_data = bytes.fromhex("02")
        # quic_stream_2 = quic_stream()
        # quic_stream_2.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        # quic_stream_2.setfieldval("Data",strem_data)
        # quic_stream_2.setfieldval("stream_id", 7)
        # quic_stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_2))

        # strem_data = bytes.fromhex("03")
        # quic_stream_3 = quic_stream()
        # quic_stream_3.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        # quic_stream_3.setfieldval("Data",strem_data)
        # quic_stream_3.setfieldval("stream_id", 11)
        # quic_stream_3 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_3))
        
        # pain_payload = crypto_frame + new_session_tikict + quic_stream_1 + quic_stream_2 + quic_stream_3

        # self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        # data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packetNumber)

        # self.UDPClientSocket.sendto(handshake_data +data,self.address)



s = iquic_server("localhost")
s.server_hello(True)   
s.Encrypted_Extensions() 


