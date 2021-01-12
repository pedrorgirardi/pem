(ns user
  (:import (java.security KeyFactory KeyPairGenerator)
           (java.security.spec X509EncodedKeySpec)
           (org.bouncycastle.util.io.pem PemObject PemReader PemWriter)
           (java.io FileReader StringWriter StringReader)))


(comment

  (def EdDSA-KeyPairGenerator
    (KeyPairGenerator/getInstance "EdDSA"))

  (def random-key-pair
    (.generateKeyPair EdDSA-KeyPairGenerator))
  ;; => #object[java.security.KeyPair 0x744a0527 "java.security.KeyPair@744a0527"]

  (.getPublic random-key-pair)
  ;; => #object[sun.security.ec.ed.EdDSAPublicKeyImpl
  ;;        0x324b390
  ;;        "algorithm = Ed25519, unparsed keybits =
  ;;         0000: E0 32 D6 20 FB CA 3F 52   89 9C C2 7E BD E6 06 8D  .2. ..?R........
  ;;         0010: 04 A5 0B 74 34 8D FB 0D   D6 A4 0F 49 FE 11 2D 84  ...t4......I..-.
  ;;         "]


  (.getType (PemObject. "PUBLIC KEY" (.getEncoded (.getPublic random-key-pair))))
  ;; => "PUBLIC KEY"

  (.getHeaders (PemObject. "PUBLIC KEY" (.getEncoded (.getPublic random-key-pair))))
  ;; => []

  ;; -- 1. Write PEM.
  ;; Public Key PEM-encoded.
  (def pem-public-key
    (with-open [string-writer (StringWriter.)
                pem-writer (PemWriter. string-writer)]
      (.writeObject pem-writer (PemObject. "PUBLIC KEY" (.getEncoded (.getPublic random-key-pair))))
      (.flush pem-writer)
      (.toString string-writer)))


  ;; -- 2. Read PEM.
  (def key-spec
    (with-open [string-reader (StringReader. pem-public-key)
                pem-reader (PemReader. string-reader)]
      (X509EncodedKeySpec. (.getContent (.readPemObject pem-reader)))))

  (-> (KeyFactory/getInstance "EdDSA")
      (.generatePublic key-spec))



  ;; ---------------------------------------


  (def key-spec
    (with-open [reader (PemReader. (FileReader. "resources/public_key.key"))]
      (X509EncodedKeySpec. (.getContent (.readPemObject reader)))))

  (-> (KeyFactory/getInstance "EdDSA")
      (.generatePublic key-spec))


  )