(ns bifrost.ipmi.crypto-test
  (:require [bifrost.ipmi.crypto :as sut]
            [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.core.nonce :as nonce]
            [buddy.core.hash :as hash]
            [buddy.core.crypto :as crypto]
            [buddy.core.nonce :as nonce]
            [clojure.test :refer :all]
            [taoensso.timbre :as log]))

(deftest cryptotest
  (testing "encrypt/decrypt 1"
    (let [iv   (nonce/random-nonce 16)
          sik  (byte-array [122 -75 -34 124 -60 80 21 -46 82 58 -109 -111 -50 -90 -9 -99 -92 0 -108 117])
          key  (bytes/slice (sut/K2 sik) 0 16)
          test "ABCDEFGHIJKLMNOPQRSTUVWXYZdsakjdsakdj"
          data (codecs/str->bytes test)
          _    (println (count data))
          eng  (crypto/block-cipher :aes :cbc)
          _    (crypto/init! eng {:key key :iv iv :opt :encrypt})
          enc  (crypto/process-block! eng data)
          _    (crypto/init! eng {:key key :iv iv :opt :decrypt})
          dec  (crypto/process-block! eng data)
          ]
      (is  (=
            (-> enc (codecs/bytes->str))
            (-> dec (codecs/bytes->str))
            )))))

(deftest test-crypto
  (testing "test no padding"
    (let [sik  (byte-array [122 -75 -34 124 -60 80 21 -46 82 58 -109 -111 -50 -90 -9 -99 -92 0 -108 117])
          {:keys [iv data padding]} (sut/encrypt sik (byte-array 16 (byte 0xa)))]
      (is (= [10 10 10 10 10 10 10 10 10 10
              10 10 10 10 10 10]
             (vec (sut/decrypt sik iv data padding))))))
  (testing "test padding 1 block"
    (let [sik  (byte-array [122 -75 -34 124 -60 80 21 -46 82 58 -109 -111 -50 -90 -9 -99 -92 0 -108 117])
          {:keys [iv data padding]} (sut/encrypt sik (byte-array 12 (byte 0xa)))]
      (is (= [10 10 10 10 10 10 10 10 10 10 10 10]
             (vec (sut/decrypt sik iv data padding ))))))
  (testing "test padding 2 block"
    (let [sik  (byte-array [122 -75 -34 124 -60 80 21 -46 82 58 -109 -111 -50 -90 -9 -99 -92 0 -108 117])
          {:keys [iv data padding]} (sut/encrypt sik (byte-array 33 (byte 0xa)))]
      (is (= [10 10 10 10 10 10 10 10 10 10
              10 10 10 10 10 10 10 10 10 10
              10 10 10 10 10 10 10 10 10 10
              10 10 10]
             (vec (sut/decrypt sik iv data padding )))))))
