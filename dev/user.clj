(ns user
  (:import (java.security KeyFactory KeyPairGenerator Security)
           (java.security.spec X509EncodedKeySpec PKCS8EncodedKeySpec)
           (sun.security.util SecurityProviderConstants)
           (sun.security.ec.ed EdDSAParameters)

           (org.bouncycastle.util.io.pem PemObject PemReader PemWriter)
           (java.io FileReader StringWriter StringReader)))


(def EdDSA-KeyPairGenerator
  (KeyPairGenerator/getInstance "Ed25519"))

(comment

  ;; Installed Providers.
  (doseq [provider (Security/getProviders)]
    (print (bean provider)
           "\n\n-------------\n\n"))

  SecurityProviderConstants/DEF_ED_KEY_SIZE
  ;; => 255

  (EdDSAParameters/getBySize nil SecurityProviderConstants/DEF_ED_KEY_SIZE)


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


  ;; -- PUBLIC KEY

  ;; Write.
  (def pem-public-key
    (with-open [string-writer (StringWriter.)
                pem-writer (PemWriter. string-writer)]
      (.writeObject pem-writer (PemObject. "PUBLIC KEY" (.getEncoded (.getPublic random-key-pair))))
      (.flush pem-writer)
      (.toString string-writer)))


  ;; Read.
  (def public-key-spec
    (with-open [string-reader (StringReader. pem-public-key)
                pem-reader (PemReader. string-reader)]
      (X509EncodedKeySpec. (.getContent (.readPemObject pem-reader)))))

  (-> (KeyFactory/getInstance "Ed25519")
      (.generatePublic public-key-spec))


  ;; -- PRIVATE KEY

  ;; Write.
  (def pem-private-key
    (with-open [string-writer (StringWriter.)
                pem-writer (PemWriter. string-writer)]
      (.writeObject pem-writer (PemObject. "PRIVATE KEY" (.getEncoded (.getPrivate random-key-pair))))
      (.flush pem-writer)
      (.toString string-writer)))


  ;; Read.
  (def private-key-spec
    (with-open [string-reader (StringReader. pem-private-key)
                pem-reader (PemReader. string-reader)]
      (PKCS8EncodedKeySpec. (.getContent (.readPemObject pem-reader)))))

  (-> (KeyFactory/getInstance "Ed25519")
      (.generatePrivate private-key-spec))

  (count (:encoded (bean private-key-spec)))
  ;; => 48



  ;; PEM FILE

  ;; -- PUBLIC KEY

  (def public-key-spec
    (with-open [reader (PemReader. (FileReader. "resources/public_key.pem"))]
      (X509EncodedKeySpec. (.getContent (.readPemObject reader)))))

  (-> (KeyFactory/getInstance "Ed25519")
      (.generatePublic public-key-spec))

  ;; -- PRIVATE KEY

  (def private-key-spec
    (with-open [reader (PemReader. (FileReader. "resources/private_key.pem"))]
      (PKCS8EncodedKeySpec. (.getContent (.readPemObject reader)))))

  (-> (KeyFactory/getInstance "Ed25519")
      (.generatePrivate private-key-spec))

  (bean private-key-spec)
  ;; => {:algorithm nil,
  ;;     :class java.security.spec.PKCS8EncodedKeySpec,
  ;;     :encoded #object["[B" 0x69665733 "[B@69665733"],
  ;;     :format "PKCS#8"}

  (count (:encoded (bean private-key-spec)))
  ;; => 48

  )