package burp;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BurpExtender implements IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor
{
    private IExtensionHelpers helpers;
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private final String secretKeyInput = "thefuckingkey";
    // hard-coded payloads
    // [in reality, you would use an extension for something cleverer than this]
    private static final byte[][] PAYLOADS =
    {
        "|".getBytes(),
        "<script>alert(1)</script>".getBytes(),
    };

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Custom intruder payloads");

        // register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(this);

        // register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(this);
    }

    //
    // implement IIntruderPayloadGeneratorFactory
    //

    @Override
    public String getGeneratorName()
    {
        return "My custom payloads";
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack)
    {
        // return a new IIntruderPayloadGenerator to generate payloads for this attack
        return new IntruderPayloadGenerator();
    }

    //
    // implement IIntruderPayloadProcessor
    //

    @Override
    public String getProcessorName()
    {
        return "Serialized input wrapper";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)
    {
        // decode the base value
        String dataParameter = decrypt(helpers.bytesToString(baseValue), secretKeyInput);
        //String dataParameter = helpers.bytesToString(baseValue);

        // parse the location of the input string in the decoded data
        int start = dataParameter.indexOf("\"password\":\"") + 12;
        if (start == -1)
            return currentPayload;
        String prefix = dataParameter.substring(0, start);
        int end = dataParameter.indexOf("\"", start);
        if (end == -1)
            end = dataParameter.length();
        String suffix = dataParameter.substring(end, dataParameter.length());

        // rebuild the serialized data with the new payload
        dataParameter = prefix + helpers.bytesToString(currentPayload) + suffix;
        String encryptedString = encrypt(dataParameter, secretKeyInput);

        return encryptedString.getBytes();
    }

    public void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String strToDecrypt, String secret)
    {
    try
    {
        setKey(secret);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    }
    catch (Exception e)
    {
        System.out.println("Error while decrypting: " + e.toString());
    }
    return null;
    }
    //
    // class to generate payloads from a simple list
    //

    class IntruderPayloadGenerator implements IIntruderPayloadGenerator
    {
        int payloadIndex;

        @Override
        public boolean hasMorePayloads()
        {
            return payloadIndex < PAYLOADS.length;
        }

        @Override
        public byte[] getNextPayload(byte[] baseValue)
        {
            byte[] payload = PAYLOADS[payloadIndex];
            payloadIndex++;
            return payload;
        }

        @Override
        public void reset()
        {
            payloadIndex = 0;
        }
    }
}
