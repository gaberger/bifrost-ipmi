(ns ipmi-aleph.test-payloads)

(def rmcp-payloads
  {:rmcp-ping                [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x80 0xc4 0x00 0x00]
   :rmcp-pong                [0x06 0x00 0xff 0x06 0x00 0x00 0x11 0xbe 0x40 0xc4 0x00 0x10
                              0x00 0x00 0x11 0xbe 0x00 0x00 0x00 0x00 0x81 0x00 0x00 0x00
                              0x00 0x00 0x00 0x00]
   :get-channel-auth-cap-req [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x09 0x20 0x18 0xc8 0x81 0x00 0x38 0x8e 0x04 0xb5]
   :get-channel-auth-cap-rsp [0x06 0x00 0xff 0x07 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x10 0x81 0x1c 0x63 0x20 0x00 0x38 0x00 0x01 0x97 0x04
                              0x03 0x00 0x00 0x00 0x00 0x09]
   :open-session-request     [0x06 0x00 0xff 0x07 0x06 0x10 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x00 0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x08
                              0x00 0x00 0x00 0x00 0x02 0x00 0x00 0x08 0x00 0x00 0x00 0x00]
   :open-session-response    [0x06 0x00 0xff 0x07 0x06 0x11 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x24 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x82 0x04 0x00 0x00 0x00 0x00 0x00 0x08 0x00 0x00 0x00 0x00
                              0x01 0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x02 0x00 0x00 0x08
                              0x00 0x00 0x00 0x00]
   :rmcp-rakp-1              [0x06 0x00 0xff 0x07 0x06 0x12 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x21 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                              0xcf 0x65 0x24 0x99 0xe6 0xba 0x89 0x44 0x4f 0x8f 0xe9 0x65
                              0x4a 0xd6 0xbc 0x4c 0x14 0x00 0x00 0x05 0x61 0x64 0x6d 0x69
                              0x6e]
   :rmcp-rakp-2              [0x06 0x00 0xff 0x07 0x06 0x13 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x28 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x2c 0x88 0x53 0xae 0xb8 0x3e 0xdd 0xa9 0x08 0xd5 0xab 0x70
                              0x87 0x92 0x77 0x65 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
                              0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef]
   :rmcp-rakp-3              [0x06 0x00 0xff 0x07 0x06 0x14 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
   :rmcp-rakp-4              [0x06 0x00 0xff 0x07 0x06 0x15 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x08 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0]
   :rmcp-close-session-req   [0x06 0x00 0xff 0x07 0x06 0x00 0x82 0x03 0x00 0x00 0x09 0x00
                              0x00 0x00 0x0b 0x00 0x20 0x18 0xc8 0x81 0x1c 0x3c 0x82 0x03
                              0x00 0x00 0xa2]
   :rmcp-close-session-rsp   [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x07 0x00
                              0x00 0x00 0x08 0x00 0x81 0x1c 0x63 0x20 0x1c 0x3c 0x00 0x88]
   :set-sess-prv-level-rsp   [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x01 0x00
                              0x00 0x00 0x09 0x00 0x81 0x1c 0x63 0x20 0x04 0x3b 0x00 0x04
                              0x9d]
   :set-sess-prv-level-req   [0x06 0x00 0xff 0x07 0x06 0x00 0x82 0x03 0x00 0x00 0x03 0x00
                              0x00 0x00 0x08 0x00 0x20 0x18 0xc8 0x81 0x04 0x3b 0x04 0x3c]
   :chassis-reset-req        [0x06 0x00 0xff 0x07 0x06 0x00 0x00 0x00 0x00 0x00 0x15 0x00
                              0x00 0x00 0x08 0x00 0x20 0x00 0xe0 0x81 0x18 0x02 0x03 0x62]
   :chassis-reset-rsp        [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x06 0x00
                              0x00 0x00 0x08 0x00 0x81 0x04 0x7b 0x20 0x18 0x02 0x00 0xc6]
   :chassis-status-req       [0x06 0x00 0xff 0x07 0x06 0x00 0x00 0x00 0x00 0x00 0x15 0x00
                              0x00 0x00 0x08 0x00 0x20 0x00 0xe0 0x81 0x18 0x01 0x66]
   :chassis-status-rsp       [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x06 0x00
                              0x00 0x00 0x0b 0x00 0x81 0x04 0x7b 0x20 0x18 0x01 0x00 0x01
                              0x00 0x00 0xc6]
   :device-id-req            [0x06 0x00 0xff 0x07 0x06 0x00 0x82 0x03 0x00 0x00 0x05 0x00 0x00
                              0x00 0x07 0x00 0x20 0x18 0xc8 0x81 0x0c 0x01 0x72]
   :device-id-rsp            [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x03 0x00 0x00
                              0x00 0x17 0x00 0x81 0x1c 0x63 0x20 0x0c 0x01 0x00 0x00 0x03 0x09
                              0x08 0x02 0x9f 0x91 0x12 0x00 0x02 0x0f 0x00 0x00 0x00 0x00 0x6a]
   :hpm-capabilities-req     [0x06 0x00 0xff 0x07 0x06 0x00 0x8c 0x26 0x00 0x00 0x04 0x00 0x00
                              0x00 0x09 0x00 0x20 0xb0 0x30 0x81 0x08 0x3e 0x00 0x02 0x37]
   :hpm-capabilities-rsp     [0x06 0x00 0xff 0x07 0x06 0x00 0xa4 0xa3 0xa2 0xa0 0x02 0x00 0x00
                              0x00 0x08 0x00 0x81 0xb4 0xcb 0x20 0x08 0x3e 0xc1 0xd9]
   :picmg-properties-req     [0x06 0x00 0xff 0x07 0x06 0x00 0x82 0x00 0x00 0x00 0x06 0x00 0x00
                              0x00 0x08 0x00 0x20 0xb0 0x30 0x81 0x10 0x00 0x00 0x6f]
   :vso-capabilities-req     [0x06 0x00 0xff 0x07 0x06 0x00 0x8c 0x26 0x00 0x00 0x0d 0x00 0x00
                              0x00 0x08 0x00 0x20 0xb0 0x30 0x81 0x14 0x00 0x03 0x68]})

; 0600ff0706008200000004000000090020 b0 308108 3e 00 02 37
; 0600ff070600 a4a3a2a0 02000000 0800 81 b4 cb2008 3e c1 d9
; 0600ff070600 a4a3a2a0 04000000 0900 20 b0 308108 3e 00 02 37
;; |                    :key | :type | :command | :function |
;; |-------------------------+-------+----------+-----------|
;; | :set-sess-prv-level-rsp |     0 |       59 |         7 |
;; |          :device-id-req |     0 |        1 |         6 |
;; |     :chassis-status-rsp |     0 |        1 |         1 |
;; |   :open-session-request |    16 |          |           |
;; | :rmcp-close-session-rsp |     0 |       60 |         7 |
;; |          :device-id-rsp |     0 |        1 |         7 |
;; |            :rmcp-rakp-4 |    21 |          |           |
;; | :rmcp-close-session-req |     0 |       60 |         6 |
;; |     :chassis-status-req |     0 |        1 |         0 |
;; |            :rmcp-rakp-3 |    20 |          |           |
;; |            :rmcp-rakp-2 |    19 |          |           |
;; | :set-sess-prv-level-req |     0 |       59 |         6 |
;; |  :open-session-response |    17 |          |           |
;; |            :rmcp-rakp-1 |    18 |          |           |
;; |      :chassis-reset-req |     0 |        2 |         0 |
;; |      :chassis-reset-rsp |     0 |        2 |         1 |


(def rmcp-payloads-cipher-1
  {:open-session-response    [0x06 0x00 0xff 0x07 0x06 0x11 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x00 0x24 0x00 0x00 0x00 0x04 0x00 0xa4 0xa3
                              0xa2 0xa0 0x01 0x18 0x00 0x02 0x00 0x00 0x00 0x08 0x01
                              0x00 0x00 0x00 0x01 0x00 0x00 0x08 0x00 0x00 0x00 0x00
                              0x02 0x00 0x00 0x08 0x00 0x00 0x00 0x00]
   :open-session-request     [0x06 0x00 0xff 0x07 0x06 0x10 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x00 0x00 0x00 0x08 0x01 0x00 0x00 0x00 0x01 0x00 0x00 0x08
                              0x01 0x00 0x00 0x00 0x02 0x00 0x00 0x08 0x01 0x00 0x00 0x00]
   :rmcp-rakp-1              [0x06 0x00 0xff 0x07 0x06 0x12 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x00 0x20 0x00 0x00 0x00 0x00 0x00 0x01 0x18
                              0x00 0x02 0x35 0xf7 0xfc 0x77 0x92 0xb8 0xf7 0x28 0xe0
                              0xfa 0x49 0xfb 0x58 0x04 0x6f 0xe5 0x14 0x00 0x00 0x04
                              0x72 0x6f 0x6f 0x74]
   :rmcp-rakp-2              [0x06 0x00 0xff 0x07 0x06 0x13 0x00 0x00 0x00 0x00 0x00 0x00
                              0x00 0x00 0x3c 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                              0x42 0xfa 0xe7 0x0f 0x38 0x1a 0x44 0x1d 0x9e 0x78 0xf3 0x87
                              0xc9 0xd0 0x49 0xa0 0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
                              0xa1 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 0x7f 0xfc 0xdb 0xc8
                              0x04 0x34 0xeb 0xb3 0x5b 0x4e 0x50 0x62 0xda 0x18 0x21 0xb2
                              0xce 0xb5 0xbc 0xb4]
   :rmcp-rakp-3               [0x06 0x00 0xff 0x07 0x06 0x14 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x1c 0x00 0x00 0x00 0x00 0x00 0xea 0x3f 0x00 0x00
                               0x59 0x71 0x80 0xf5 0xfd 0x33 0x58 0x5d 0x3a 0xde 0x5c 0xab
                               0xaf 0x34 0xa4 0xfc 0xf3 0xf8 0xaf 0x65]
   :rmcp-rakp-4               [0x06 0x00 0xff 0x07 0x06 0x15 0x00 0x00 0x00 0x00 0x00 0x00
                               0x00 0x00 0x14 0x00 0x00 0x00 0x00 0x00 0xa4 0xa3 0xa2 0xa0
                               0x8b 0xc0 0x18 0x2d 0x9a 0x9e 0x52 0x8b 0x12 0xf4 0xc0 0x77]})



