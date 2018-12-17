(ns ipmi-aleph.handlers)

(defn presence-pong [tag]
  {:version 6,          
  :reserved 0,
  :sequence 255,
  :rmcp-class
  {:asf-payload
   {:iana-enterprise-number 4542,
    :asf-message-header
    {:asf-message-type 64,
     :reserved2 [0 0 0 0 0 0],
     :data-length 16,
     :oem-defined 0,
     :supported-interactions 0,
     :message-tag tag,
     :reserved1 0,
     :oem-iana-number 4542,
     :supported-entities 0}},
   :type :asf-session}})

(defn auth-capabilities-response []
  {:oem-id [0 0 0],
   :oem-aux-data 0,
   :auth-compatibility
   {:reserved 0,
    :key-generation false,
    :per-message-auth false,
    :user-level-auth false,
    :non-null-user-names true,
    :null-user-names false,
    :anonymous-login-enabled false},
   :version-compatibility
   {:version-compatibility true,
    :reserved false,
    :oem-proprietary-auth false,
    :password-key true,
    :md5-support true,
    :md2-support true,
    :no-auth-support true},
   :command 56,
   :channel {:reserved 0, :channel-num 1},
   :source-lun 0,
   :source-address 32,
   :supported-connections {:reserved 0, :ipmi-2-0 true, :ipmi-1-5 true},
   :checksum 9,
   :header-checksum 99,
   :target-address 129,
   :network-function {:function 7, :target-lun 0},
   :command-completion-code 0})
