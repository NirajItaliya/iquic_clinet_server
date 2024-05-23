from enum import Enum


class SessionInstance:
    __instance = None
    certificate = bytes.fromhex("308205f130820459a003020102020900cb2d80995a69525c300d06092a864886f70d01010b0500304d310b300906035504061302585931263024060355040a0c1d507974686f6e20536f66747761726520466f756e646174696f6e2043413116301406035504030c0d6f75722d63612d736572766572301e170d3138303832393134323331365a170d3238303730373134323331365a305f310b30090603550406130258593117301506035504070c0e436173746c6520416e746872617831233021060355040a0c1a507974686f6e20536f66747761726520466f756e646174696f6e3112301006035504030c096c6f63616c686f7374308201a2300d06092a864886f70d01010105000382018f003082018a02820181009f282f3741ef7f6463166216e901146229ca3a98923d08d35e69fec0f3d4c4fb0e58dc64b04bcbb3aa9e42e9079b6733cdb9e83c1d8a13c0df39677c4cd37ebf430f4a85056d87e5c302a33ed7d7b9287918731837777648d47818d7bd1e6a468b06f30337950ba053b022cd8fb70336a3d72377999f4ae5adb48ebe7c2aa8a7cfe5f1c7ab1bd897d861f7f69de25b05a84d9b989dd000f6a62fd3b6166a3b90d4449628f8c76064e732fbb8c48ce26c2d665ddd8ceaefc88cd3ba838dba48a15a443590931d3580857f0b22acf43819a1e30790a66e3ea6553b138af80fcdae6aea1c5b0f22caece7093b400563bb9fd7d6c9299ff50642598c47005a4142ceb3515a800fb9e115d4eaa50f5b4626849e31381e201c70f5be300a12c459effeb37313323a6f8cd436ca4531f83568d55a99d8f1769519d461b53a47f4c8f27292a117e0f665dcb6b505edaaed8675c32751e76dd777e7f710ee3f83e8a611348a9fc83209fe91be26f5ef92f8af6595d425d01fb805c19602a1de961d8ab94d0203010001a38201c0308201bc30140603551d11040d300b82096c6f63616c686f7374300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e041604148fea1de3335c0016b38b6f6b6fd34ccbb5cb7c55307d0603551d23047630748014ddbfcadae6d134ba377521ca6f9a0828f235b648a151a44f304d310b300906035504061302585931263024060355040a0c1d507974686f6e20536f66747761726520466f756e646174696f6e2043413116301406035504030c0d6f75722d63612d736572766572820900cb2d80995a69525b30818306082b0601050507010104773075303c06082b060105050730028630687474703a2f2f7465737463612e707974686f6e746573742e6e65742f7465737463612f70796361636572742e636572303506082b060105050730018629687474703a2f2f7465737463612e707974686f6e746573742e6e65742f7465737463612f6f6373702f30430603551d1f043c303a3038a036a0348632687474703a2f2f7465737463612e707974686f6e746573742e6e65742f7465737463612f7265766f636174696f6e2e63726c300d06092a864886f70d01010b0500038201810027f58c5910f4c6e72800bfba8d7b1303f11ca65fb30655a422b9dbb2d546bdf70cdd436eb4796567210c2a55ee408e859f9f47bb0a2a4db6647498a07faedcf12edb427718e0758b263568c341ed6bc877726f6a9a5d556902fd5a54c857cbb0650316e20f00399966a09b889317e25a2d79355f975778c4aff5995e86abd311ad1aa20dfa5210b9febf9dce33d986b29c16f8d675088adb0ae5b42b167fb4f92a9fc3d277d7cd651ef46c1eeb59b9f0ae5fa41fcc4ac4b97aa9d96b32683be165b084b790c4aefef4374f21a0de9f3ab1e5cc1604663f0b41dc423d203eecb7952b3557fabe7fb63abaca4f58fe753e08892c8cb05d2ef989102bf941464f3c00b727d36524281723263142ea7e4e93e47b6854ca9f46f3ef2be9850cb584b2d5353480752bf09123b808018eb90a54d4fb3452fed945f0803bb6c16f82d11ff23b08f646a69627614b58327a0e1d59c544ad5e1a7933c1d4052f4ad3d842428d33e363cad587979b4db81a0334bb1cd2023f5923e223808863c2f0a263a88b")
    certificate_private_key = bytes.fromhex("308204a40201000282010100c9b3")
    total_handshakepacket = 0
    connection_id = -1
    initial_source_connection_id = "" 
    initial_destination_connection_id = ""
    server_config_id = ""
    source_address_token = ""
    public_value = None # object
    public_values_bytes = ""
    private_value = None
    client_initial_destination_connection_id = ""
    shared_key = b''
    _ec_private_key = ""
    _x25519_private_key = ""
    _x448_private_key = ""
    configuration = None
    chlo = ""
    shlo = ""
    tlschlo= b''
    tlsshalo= b''
    crypto_extensions = b''
    crypto_cert = b''
    crypto_certverify =b''
    crypto_finished =b''
    server_handshake_secret = b''
    client_handshake_secret = b''
    client_handshake_traffic_secret= b''
    server_handshake_traffic_secret= b''
    client_appliction_traffic_secret= b''
    server_appliction_traffic_secret= b''
    handshake_done = False
    randome_value = b''

    scfg = ""
    cert_chain = ""
    cert_localhost = ""

    initial_keys = {}
    final_keys = {}
    peer_public_value_initial = ""
    peer_public_value_final = ""
    div_nonce = ""
    message_authentication_hash = ""
    associated_data = ""
    packet_number = ""
    largest_observed_packet_number = -1
    shlo_received = False
    nr_ack_send = 0
    connection_id_as_number = -1
    destination_ip = "127.0.0.1"  # Home connectiopns
    # destination_ip = "192.168.43.228"   # hotspot connections
    zero_rtt = False
    last_received_rej = ""  # We are only interested in the last REJ for the initial keys.
    last_received_shlo = ""
    app_keys = {'type': None, 'mah': "", 'key': {}}
    first_packet_of_new_command = False
    currently_sending_zero_rtt = False  # If it is set to True, then we do not need to store the REJ otherwise it will not work.

    @staticmethod
    def get_instance():
        if SessionInstance.__instance is None:
            return SessionInstance()
        else:
            return SessionInstance.__instance

    def __init__(self):
        if SessionInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.server_config_id = "-1"
            self.source_address_token = "-1"
            SessionInstance.__instance = self

    @staticmethod
    def reset():  
        SessionInstance.__instance = None      

