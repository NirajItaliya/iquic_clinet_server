import socket
from aioquic.quic.crypto import CryptoContext,CryptoPair

import subprocess
import re
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary,decrypte_length
import random

from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance
from crypto.Secret import dhke, Crypto,utils
from CryptoFrame import CryptoFrame ,ACKFrame,ACKFrameModify,TLSFinish,CryptoFrameModify,CryptoFrameOffsetModify
from events.Events import *

from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed, quic_offset_stream_Modify_0f,quic_offset_stream_Modify,retire_connection_id, quic_stream_0b,quic_stream_08,handshake_done_frame
import os
import qpack 
from aioquic.quic.crypto import CryptoContext,CryptoPair
from  Keylog import KeyFile
from aioquic.h3.connection import encode_frame
# from trigger_client import reference_client

# c = reference_client()
UDPClientSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
ip = "localhost"
port = 5050
UDPClientSocket.bind((ip, port))

serverhello = False
handshkepacket = False
hadshake_done = False



class iquic_server :
    def __init__(self,s) -> None:
        self.cryptoContext = CryptoContext()
        self.crypto_pair = CryptoPair() 
        self.serverhello = False
        self.handshkepacket = False
        self.hadshake_done = False
        self.UDPClientSocket  = UDPClientSocket
        self.address = None
        self.handshakeoffset = 25
        self.applicationoffest = 9

    def reset(self, reset_server, reset_run=True):
        if reset_run:
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
            self.serverhello = False
            self.handshkepacket = False
            self.hadshake_done = False
    
    def server_hello(self,only_reset):
        self.reset(only_reset)
        try :
            datarev_1,self.address = self.UDPClientSocket.recvfrom(1300)
            while  len(datarev_1) < 1000 :
                 datarev_1,self.address = self.UDPClientSocket.recvfrom(1300)
            DCID = datarev_1[6:14]
            SessionInstance.get_instance().client_initial_destination_connection_id= bytes.hex(DCID)
            SCID = datarev_1[15:15+8]
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            try :
                self.crypto_pair.setup_initial(cid = DCID, is_client = False, version = 0x1)
                plain_header, pain_payload, packet_number = self.crypto_pair.decrypt_packet(datarev_1, 26, 0)
            except: return  b"Error"
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
      
        padding = bytes.fromhex("00"*1056)
        pain_payload = _ackFrame + crypto_frame + bytes.fromhex(ServerHello) + padding
        try: 
            data = self.crypto_pair.encrypt_packet(plain_header, pain_payload, 0)
            self.UDPClientSocket.sendto(data,self.address)
            return b"-"
        except: return b"Error"
        

    def Encrypted_Extensions2(self):
        packetNumber = PacketNumberInstance.get_instance().get_next_packet_number()

        _encryptedExtensions = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().get_EncryptedExtensions().data))
        SessionInstance.get_instance().crypto_extensions = _encryptedExtensions

        cryptoFrame = CryptoFrame()
        cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(_encryptedExtensions).to_bytes(2, byteorder='big'))[1:]))
        crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))

        pain_payload = crypto_frame + _encryptedExtensions

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
        data_EE = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packetNumber)
        self.UDPClientSocket.sendto(data_EE,self.address)

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
        data_EE = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packetNumber)
        # self.UDPClientSocket.sendto(data_EE,self.address)

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
        handshake_data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packetNumber)
        dhke.appliction_traffic_computation()
        KeyFile.FileGenret()



        #application data 
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        header = QUICHeader.QUICShortHeader()
        header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id))
        header.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(header))

        new_session_tikict = bytes.fromhex(extract_from_packet_as_bytestring(CryptoFrame().new_session_ticket().data))
        cryptoFrame = CryptoFrame()
        cryptoFrame.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(new_session_tikict).to_bytes(2, byteorder='big'))[1:]))
        crypto_frame = bytes.fromhex(extract_from_packet_as_bytestring(cryptoFrame))
        
        strem_data = bytes.fromhex("0004100150000710080121013301ab60374201")
        quic_stream_1 = quic_stream()
        quic_stream_1.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        quic_stream_1.setfieldval("Data",strem_data)
        quic_stream_1.setfieldval("stream_id", 3)
        quic_stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_1))

        strem_data = bytes.fromhex("02")
        quic_stream_2 = quic_stream()
        quic_stream_2.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        quic_stream_2.setfieldval("Data",strem_data)
        quic_stream_2.setfieldval("stream_id", 7)
        quic_stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_2))

        strem_data = bytes.fromhex("03")
        quic_stream_3 = quic_stream()
        quic_stream_3.setfieldval("Length",bytes.fromhex("4" + bytes.hex(len(strem_data).to_bytes(2, byteorder='big'))[1:]))
        quic_stream_3.setfieldval("Data",strem_data)
        quic_stream_3.setfieldval("stream_id", 11)
        quic_stream_3 = bytes.fromhex(extract_from_packet_as_bytestring(quic_stream_3))

        pain_payload = crypto_frame + new_session_tikict + quic_stream_1 + quic_stream_2 + quic_stream_3
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packet_number)
        self.UDPClientSocket.sendto(data_EE,self.address)
        self.UDPClientSocket.sendto(handshake_data + data,self.address)

        pattern = b""
        try :
            recve_finish = self.UDPClientSocket.recv(1300)

            while  len(recve_finish) < 100 or len(recve_finish) > 1000 :
                recve_finish = self.UDPClientSocket.recv(1300)
            # utils.findpakettype(recve_finish[0:1]) != "handshake" and   

            if utils.findpakettype(recve_finish[0:1]) == "handshake" :

                packet_length = decrypte_length(recve_finish[23:25])
                handshake = recve_finish[:25+packet_length]
                application = recve_finish[25+packet_length:]
                self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().client_handshake_traffic_secret, version = 1)
                plain_header, pain_payload, packet_number, crypto = self.cryptoContext.decrypt_packet(handshake, self.handshakeoffset, 0)
                clinet_finish_verfiy_data = pain_payload[-48:] 
                pattern += b"Finish"
                # print(bytes.hex(clinet_finish_verfiy_data))
                # print(bytes.hex(dhke.finished_verify_data(cipher_suite = 0x1302, client_secret  = SessionInstance.get_instance().client_handshake_secret)))

                self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().client_appliction_traffic_secret, version = 1)
                plain_header, pain_payload, packet_number, crypto = self.cryptoContext.decrypt_packet(application, self.applicationoffest, 0)
            else:
                return "Error"
            
            recve_headear = self.UDPClientSocket.recv(1300)
            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().client_appliction_traffic_secret, version = 1)
            plain_header, pain_payload, packet_number, crypto = self.cryptoContext.decrypt_packet(recve_headear, self.applicationoffest, 0)
            pattern += b"+GET"
            self.send_application_Ack(packet_number)

            return pattern    
        except :
           print("exp")

    def send_application_Ack (self,packetnumber) :  
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        aCKFrame = ACKFrameModify()
        aCKFrame.setfieldval("ACK_delay", bytes.fromhex("24")) 
        aCKFrame.setfieldval("Largest_Acknowledged",packetnumber)
        aCKFrame.setfieldval("First_ACK_Range",1)
        _ackFrame = bytes.fromhex(extract_from_packet_as_bytestring(aCKFrame))

        pain_payload = _ackFrame
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packet_number)
        self.UDPClientSocket.sendto(data,self.address)

    def send_handshake_done(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        _handshake_done_frame = bytes.fromhex(extract_from_packet_as_bytestring(handshake_done_frame()))

        _new_connection_id_data = b""
        
        for i in range(1,8) :
            new_connection_id_data = new_connection_id()
            new_connection_id_data.setfieldval("Sequence" ,i)
            new_connection_id_data.setfieldval("CID" ,os.urandom(8))
            new_connection_id_data.setfieldval("Stateless_Reset_Token" ,os.urandom(16))
            _new_connection_id_data +=  bytes.fromhex(extract_from_packet_as_bytestring(new_connection_id_data))

        quic_offset_stream_1 = quic_offset_stream()
        quic_offset_stream_1.setfieldval("stream_id",7)
        quic_offset_stream_1.setfieldval("offset",1)
        quic_offset_stream_1.setfieldval("Length",bytes.fromhex("4003"))
        quic_offset_stream_1.setfieldval("Data",bytes.fromhex("3ef11f"))
        _quic_offset_stream_1 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_1))

        try :
            pain_payload = _handshake_done_frame + _new_connection_id_data + _quic_offset_stream_1
            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
            data = self.cryptoContext.encrypt_packet(plain_header, pain_payload, packet_number)
            self.UDPClientSocket.sendto(data,self.address)
            recve_ack = self.UDPClientSocket.recv(1300)
            return  b"-"
        except: return b"Error"
    

    def send_http(self) :

        # if self.serverhello == True and self.handshkepacket == True and self.hadshake_done == True  :
        #     return b"-"
        # else :
        #     return b"EXP"
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))
    
        quic_offset_stream_1 = quic_stream()
        quic_offset_stream_1.setfieldval("stream_id",0)
        quic_offset_stream_1.setfieldval("Length",bytes.fromhex("4028"))
        quic_offset_stream_1.setfieldval("Data",bytes.fromhex("0526000000d1d7508aa0e41d139d09b8d34cb351876109f5415722115f5089198fdad31180ae05c1"))
        _quic_offset_stream_1 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_1))

        quic_offset_stream_2 = quic_stream()
        quic_offset_stream_2.setfieldval("stream_id",15)
        quic_offset_stream_2.setfieldval("Length",bytes.fromhex("4002"))
        quic_offset_stream_2.setfieldval("Data",bytes.fromhex("0100"))
        _quic_offset_stream_2 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_2))

        plain_payload = _quic_offset_stream_1 + _quic_offset_stream_2
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        try: 
            data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
            self.UDPClientSocket.sendto(data,self.address) # 1
        except: return b"Error"

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        quic_offset_stream_1 = quic_offset_stream()
        quic_offset_stream_1.setfieldval("stream_id",0)
        quic_offset_stream_1.setfieldval("offset",28)
        quic_offset_stream_1.setfieldval("Length",bytes.fromhex("402f"))
        quic_offset_stream_1.setfieldval("Data",bytes.fromhex("012d0000d95f4d89198fdad31180ae05c15696dc34fd28275486bb141004d28166e362b82794c5a37f5483085f73f4"))
        _quic_offset_stream_1 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_1))

        plain_payload =  _quic_offset_stream_1
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
        try: 
            data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
            self.UDPClientSocket.sendto(data,self.address) # 1
        except: return b"Error"

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        quic_offset_stream_1 = quic_offset_stream_Modify()
        quic_offset_stream_1.setfieldval("stream_id",0)
        quic_offset_stream_1.setfieldval("offset",bytes.fromhex("4057"))
        quic_offset_stream_1.setfieldval("Length",bytes.fromhex("448f"))
        quic_offset_stream_1.setfieldval("Data",bytes.fromhex("0044ac3c21444f43545950452068746d6c3e0a3c68746d6c3e0a202020203c686561643e0a20202020202020203c6d65746120636861727365743d227574662d38222f3e0a20202020202020203c7469746c653e61696f717569633c2f7469746c653e0a20202020202020203c6c696e6b2072656c3d227374796c6573686565742220687265663d222f7374796c652e637373222f3e0a202020203c2f686561643e0a202020203c626f64793e0a20202020202020203c68313e57656c636f6d6520746f2061696f717569633c2f68313e0a20202020202020203c703e0a2020202020202020202020205468697320697320612074657374207061676520666f72203c6120687265663d2268747470733a2f2f6769746875622e636f6d2f61696f7274632f61696f717569632f223e61696f717569633c2f613e2c0a20202020202020202020202061205155494320616e6420485454502f3320696d706c656d656e746174696f6e207772697474656e20696e20507974686f6e2e0a20202020202020203c2f703e0a0a20202020202020203c703e0a202020202020202020202020436f6e67726174756c6174696f6e732c20796f75206c6f6164656420746869732070616765207573696e6720485454502f33210a20202020202020203c2f703e0a0a20202020202020203c68323e417661696c61626c6520656e64706f696e74733c2f68323e0a20202020202020203c756c3e0a2020202020202020202020203c6c693e3c7374726f6e673e474554202f3c2f7374726f6e673e2072657475726e732074686520686f6d65706167653c2f6c693e0a2020202020202020202020203c6c693e3c7374726f6e673e474554202f4e4e4e4e4e3c2f7374726f6e673e2072657475726e73204e4e4e4e4e206279746573206f6620706c61696e20746578743c2f6c693e0a2020202020202020202020203c6c693e3c7374726f6e673e504f5354202f6563686f3c2f7374726f6e673e2072657475726e7320746865207265717565737420646174613c2f6c693e0a2020202020202020202020203c6c693e0a202020202020202020202020202020203c7374726f6e673e434f4e4e454354202f77733c2f7374726f6e673e2072756e73206120576562536f636b6574206563686f20736572766963652e0a20202020202020202020202020202020596f75206d7573742073657420746865203c656d3e3a70726f746f636f6c3c2f656d3e2070736575646f2d68656164657220746f203c656d3e22776562736f636b6574223c2f656d3e2e0a2020202020202020202020203c2f6c693e0a2020202020202020202020203c6c693e0a202020202020202020202020202020203c7374726f6e673e434f4e4e454354202f77743c2f7374726f6e673e2072756e732061205765625472616e73706f7274206563686f20736572766963652e0a20202020202020202020202020202020596f75206d7573742073657420746865203c656d3e3a70726f746f636f6c3c2f656d3e2070736575646f2d68656164657220746f203c656d3e227765627472616e73706f7274223c2f656d3e2e0a2020202020202020202020203c2f6c693e0a20"))
        _quic_offset_stream_1 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_1))

        plain_payload =  _quic_offset_stream_1
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
        try: 
            data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
            self.UDPClientSocket.sendto(data,self.address) # 1
        except: return b"Error"

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        plain_header =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        quic_offset_stream_1 = quic_offset_stream_Modify_0f()
        quic_offset_stream_1.setfieldval("stream_id",0)
        quic_offset_stream_1.setfieldval("offset",bytes.fromhex("44e6"))
        quic_offset_stream_1.setfieldval("Length",bytes.fromhex("4020"))
        quic_offset_stream_1.setfieldval("Data",bytes.fromhex("202020202020203c2f756c3e0a202020203c2f626f64793e0a3c2f68746d6c3e"))
        _quic_offset_stream_1 =  bytes.fromhex(extract_from_packet_as_bytestring(quic_offset_stream_1))

        plain_payload =  _quic_offset_stream_1
        self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
        try: 
            data = self.cryptoContext.encrypt_packet(plain_header, plain_payload, packet_number)
            self.UDPClientSocket.sendto(data,self.address) # 1
        except: return b"Error"


        return b"closed"
    
    def send(self, command):
        try:
            if isinstance(command, SendServerHelloEvent):
                print("Sending InitialSHLO")
                return self.server_hello(True)
            elif isinstance(command, SendhandshakeEvent):
                print("Sending hadshakePacket ")
                return self.Encrypted_Extensions()
            elif isinstance(command, SendhandshakedoneEvent):
                print("Sending handshake done")
                return self.send_handshake_done()
            elif isinstance(command, SendHttpData):
                print("Sending Data")
                return self.send_http()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            print("error")  




s = iquic_server("localhost")
print(s.server_hello(True))   
print(s.Encrypted_Extensions()) 
print(s.send_handshake_done())
print(s.send_http())


