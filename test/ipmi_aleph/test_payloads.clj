(ns ipmi-aleph.test-payloads)

(def rmcp-payloads
  {:rmcp-ping [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x80 0xc4 0x00 0x00]
   :rmcp-pong [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x40 0xc4 0x00 0x10 0x00 0x00 0x11 0xbe 0 0 0 0 81 0 0 0 0 0 0 0]
   :get-channel-auth-cap-req  [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x00 0x09 0x20 0x18 0xc8 0x81 0x00 0x38
                               0x8e 0x04 0xb5]
   :get-channel-auth-cap-rsp  [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x00 0x10 0x81 0x1c 0x63 0x20 0x00 0x38
                               0x00 0x01 0x97 0x04 0x03 0x00 0x00 0x00 0x00 0x09]
   :open-session-request [0x06 0x00 0xff 0x07 0x06 0x10 0x00 0x00 0x00 0x00
                          0x00 0x00 0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00
                          0xa4 0xa3 0xa2 0xa0 0x00 0x00 0x00 0x08 0x01 0x00
                          0x00 0x00 0x01 0x00 0x00 0x08 0x01 0x00 0x00 0x00
                          0x02 0x00 0x00 0x08 0x01 0x00 0x00 0x00]
   :open-session-response [0x06 0x00 0xff 0x07 0x06 0x11 0x00 0x00 0x00 0x00
                           0x00 0x00 0x00 0x00 0x24 0x00 0x00 0x00 0x00 0x00
                           0xa4 0xa3 0xa2 0xa0 0x82 0x04 0x00 0x00 0x00 0x00
                           0x00 0x08 0x01 0x00 0x00 0x00 0x01 0x00 0x00 0x08
                           0x01 0x00 0x00 0x00 0x02 0x00 0x00 0x08 0x01 0x00
                           0x00 0x00]
   :rmcp-rakp-1 [0x06 0x00 0xff 0x07 0x06 0x12 0x00 0x00 0x00 0x00 0x00 0x00
                 0x00 0x00 0x21 0x00 0x00 0x00 0x00 0x00 0x82 0x04 0x00 0x00
                 0x14 0xaf 0x31 0x31 0xe8 0x75 0xa5 0xee 0x2c 0x2f 0x16 0xf6
                 0x80 0xd3 0x52 0x06 0x14 0x00 0x00 0x05 0x41 0x44 0x4d 0x49
                 0x4e]
   :rmcp-rakp-2 [0x06 0x00 0xff 0x07 0x06 0x13 0x00 0x00 0x00 0x00 0x00 0x00
                 0x00 0x00 0x3c 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                 0x2c 0x88 0x53 0xae 0xb8 0x3e 0xdd 0xa9 0x08 0xd5 0xab 0x70
                 0x87 0x92 0x77 0x65 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
                 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 0x44 0x33 0x57 0x4e
                 0xd9 0xfe 0x9c 0x8d 0x76 0x27 0x1c 0xfc 0x45 0x97 0x83 0x4b
                 0x7d 0x79 0x74 0x7d]})