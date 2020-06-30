class SecMethodGenerator {
    String block;
    //String methodName;
    String nameBlockMethod;
    private final static String CR = "\n";

    public SecMethodGenerator(String block) {
        this.block = block;
        /*this.methodName = methodName;
        this.nameBlockMethod = block + "__" + methodName;*/
    }

    public String defineSecureMethod(String methodName) {
        String ret;
        switch (methodName) {
            case "aencrypt":
                ret += aencrypt();
                break;
            case "adecrypt":
                ret += adecrypt();
                break;
            case "sencrypt":
                ret += sencrypt();
                break;
            case "sdecrypt":
                ret += sdecrypt();
                break;
            case "pk":
                ret += pk();
                break;
            case "cert":
                ret += cert();
                break;
            case "verifyCert":
                ret += verifyCert();
                break;
            default:
                ret = " ";
        }
        return ret;
    }

    private String cert() {
        String ret = " ";
        //load_cert(entity *obj, char name)
        ret += "load_cert(entity," + this.block + ");" + CR;
        return ret;
    }

    private String pk() {
        String ret = " ";
        //load_private_key(entity *obj, char name)
        ret += "load_private_key(entity," + this.block + ");" + CR;
        return ret;
    }

    private String verifyCert() {
        String ret = " ";
        // verify_cert(entity *obj, char cert_name)
        ret += "verify_cert(entity," + this.block + ");" + CR;

        return ret;
    }

    private String sencrypt() {
        String ret = " ";
        ret +="ciphertext_len = do_encrypt(my__attr, strlen((char *)my__attr), ciphertext, "+this.block+");";

        return ret;
    }

    private String sdecrypt() {
        String ret = " ";
        ret +="do_decrypt(texttodecrypt, ciphertext_len, decryptedtext,"+this.block+ ");";
        return ret;
    }

    private String aencrypt() {
        String ret = " ";

        return ret;
    }

    private String adecrypt() {
        String ret = " ";

        return ret;
    }
}