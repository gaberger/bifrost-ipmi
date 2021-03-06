(ns bifrost.ipmi.gloss-test
  (:require [clojure.test :refer :all]
            [gloss.core :refer :all]
            [gloss.io :refer :all]))

(deftest test-variable-encoder
  (let [codec (compile-frame (repeated :ubyte :prefix :ubyte))
        encoded (encode codec [0 0 0])]
    (is (=
         (decode codec encoded)
         [0 0 0]))))

(deftest lil-endian
  (let [codec (compile-frame [:uint32-le])
        encoded (encode codec [0xa4 0xa3 0xa2 0xa0])]
    (is (= [2695013284]
           (decode codec (byte-array [0xa4 0xa3 0xa2 0xa0]))))))

(deftest encode-decode
  (let [codec (compile-frame {:a :ubyte :b :ubyte})
        encoded (encode codec {:a 1 :b 2})]
    (is (=
         (decode codec encoded)
         {:a 1 :b 2}))))

(deftest repeat-encoder
  (let [codec (compile-frame {:a :ubyte :b (repeat 2 :ubyte)})
        data {:a 1 :b [0 0]}
        encoded (encode codec data)]
    (is (=
         (decode codec encoded)
         data))))

(deftest composed-codec
  (let [codec-body (compile-frame {:c :ubyte})
        _ (defcodec codec {:a :ubyte :b codec-body})
        data {:a 1 :b {:c 1}}
        encoded (encode codec data)]
    (is (=
         data
         (decode codec encoded)))))

(deftest bitmap-codec
  (let [codec-body (compile-frame {:a (bit-map :a 1 :b 7)})
        data {:a {:a false :b 7}}
        encoded (encode codec-body data)]
    (is (=
         data
         (decode codec-body encoded)))))


(deftest test-repeat
  (let [f (repeated :ubyte
                    :prefix (gloss.core.codecs/constant-prefix 8))
                    
        codec (compile-frame f)
        decoded (decode codec (byte-array [0 0 0 0 0 0 0 0]))]
    (is (= [0 0 0 0 0 0 0 0]
           decoded))))

    


(deftest nested-encoder
  (let [tag              (compile-frame
                          (enum :byte
                                {:auth-request    0
                                 :session-request 1}))
        auth-request     (compile-frame
                          {:type    :auth-request
                           :payload (compile-frame {:a :byte})})
        session-request  (compile-frame
                          {:type    :session-request
                           :payload (compile-frame {:b :byte})})
        body-header      (compile-frame
                          (header tag {:auth-request    auth-request
                                       :session-request session-request}
                                  :type))
        packet-header    (compile-frame
                          (ordered-map
                           :source :byte
                           :destination :byte
                           :payload body-header))
        auth-map         {:source 0 :destination 0 :payload {:type :auth-request :payload {:a 0x01}}}
        session-map      {:source 0 :destination 0 :payload {:type :session-request :payload {:b 0x01}}}
        encoded-auth-map (encode packet-header auth-map)]
        ;encoded-sess-map (encode packet-header session-map)]
    (is (= (decode packet-header (encode packet-header auth-map))
           {:destination 0,
            :payload   {:payload {:a 1}, :type :auth-request},
            :source    0}))
    (is (=
         (decode packet-header (encode packet-header session-map))
         {:destination 0,
          :payload     {:payload {:b 1}, :type :session-request},
          :source      0}))))

(deftest composed-codec-function
  (let [codec-fn  (finite-frame 10 {:payload :ubyte})
        codec-body (compile-frame {:c :ubyte :d codec-fn})
        data {:a 1 :b {:c 1}}
        encoded (encode codec-body data)]
    (is (=
         data
         (decode codec encoded)))))

(deftest composed-codec-function
  (let [codec-fn  (fn [n] (compile-frame (finite-frame n
                                                     (repeated :ubyte :prefix :none))))
        codec-body (compile-frame {:c :ubyte :d (codec-fn 10)})
        data {:c 0, :d [0 1 2 3 4 5 6 7 8 9]}
        encoded (encode codec-body data)]
    (is (=
         data
         (decode codec-body (byte-array [0 0 1 2 3 4 5 6 7 8 9]))))))
