package com.fsck.k9.ui.crypto;


import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import android.content.Intent;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import com.fsck.k9.K9;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.mail.internet.MimeUtility;
import okio.ByteString;
import org.openintents.openpgp.OpenPgpInlineKeyUpdate;
import org.openintents.openpgp.util.OpenPgpApi;


public class InbomeOperations {

    public static final String INBOME_PARAM_KEY_DATA = "key";
    public static final String INBOME_PARAM_TO = "to";
    public static final String INBOME_HEADER = "Inbome";
    private static final String INBOME_PARAM_TYPE = "type";

    InbomeOperations() {
    }

    private boolean addKeyFromInbomeHeaderToIntentIfPresent(MimeMessage currentMessage, Intent decryptIntent) {
        InbomeHeader inbomeHeader = getValidInbomeHeader(currentMessage);
        if (inbomeHeader == null) {
            return false;
        }

        String messageFromAddress = currentMessage.getFrom()[0].getAddress();
        if (!inbomeHeader.to.equalsIgnoreCase(messageFromAddress)) {
            return false;
        }

        Date messageDate = currentMessage.getSentDate();
        Date internalDate = currentMessage.getInternalDate();
        Date effectiveDate = messageDate.before(internalDate) ? messageDate : internalDate;

        OpenPgpInlineKeyUpdate data = OpenPgpInlineKeyUpdate.createOpenPgpInlineKeyUpdate(inbomeHeader.keyData, effectiveDate);
        decryptIntent.putExtra(OpenPgpApi.EXTRA_INLINE_KEY_DATA, data);
        return true;
    }

    void processUnsignedMessage(OpenPgpApi openPgpApi, MimeMessage currentMessage) {
        Intent intent = new Intent(OpenPgpApi.ACTION_UPDATE_TRUST_ID);
        boolean hasInlineKeyData = addKeyFromInbomeHeaderToIntentIfPresent(currentMessage, intent);
        if (hasInlineKeyData) {
            String trustId = currentMessage.getFrom()[0].getAddress();
            intent.putExtra(OpenPgpApi.EXTRA_TRUST_IDENTITY, trustId);
            openPgpApi.executeApi(intent, (InputStream) null, null);
        }
    }

    @Nullable
    @VisibleForTesting
    InbomeHeader getValidInbomeHeader(MimeMessage currentMessage) {
        String[] headers = currentMessage.getHeader(INBOME_HEADER);
        ArrayList<InbomeHeader> inbomeHeaders = parseAllInbomeHeaders(headers);

        boolean isSingleValidHeader = inbomeHeaders.size() == 1;
        return isSingleValidHeader ? inbomeHeaders.get(0) : null;
    }

    @NonNull
    private ArrayList<InbomeHeader> parseAllInbomeHeaders(String[] headers) {
        ArrayList<InbomeHeader> inbomeHeaders = new ArrayList<>();
        for (String header : headers) {
            InbomeHeader inbomeHeader = parseInbomeHeader(header);
            if (inbomeHeader != null) {
                inbomeHeaders.add(inbomeHeader);
            }
        }
        return inbomeHeaders;
    }

    @Nullable
    private InbomeHeader parseInbomeHeader(String headerValue) {
        Map<String,String> parameters = MimeUtility.getAllHeaderParameters(headerValue);

        String type = parameters.remove(INBOME_PARAM_TYPE);
        if (type != null && !type.equals("p")) {
            Log.e(K9.LOG_TAG, "inbome: unsupported type parameter " + type);
            return null;
        }

        String base64KeyData = parameters.remove(INBOME_PARAM_KEY_DATA);
        if (base64KeyData == null) {
            Log.e(K9.LOG_TAG, "inbome: missing key parameter");
            return null;
        }

        ByteString byteString = ByteString.decodeBase64(base64KeyData);
        if (byteString == null) {
            Log.e(K9.LOG_TAG, "inbome: error parsing base64 data");
            return null;
        }

        String to = parameters.remove(INBOME_PARAM_TO);
        if (to == null) {
            Log.e(K9.LOG_TAG, "inbome: no to header!");
            return null;
        }


        if (hasCriticalParameters(parameters)) {
            return null;
        }

        return new InbomeHeader(parameters, to, byteString.toByteArray());
    }

    private boolean hasCriticalParameters(Map<String, String> parameters) {
        for (String parameterName : parameters.keySet()) {
            if (parameterName != null && !parameterName.startsWith("_")) {
                return true;
            }
        }
        return false;
    }

    boolean hasInbomeHeader(MimeMessage currentMessage) {
        return currentMessage.getHeader(INBOME_HEADER).length > 0;
    }

    @VisibleForTesting
    class InbomeHeader {
        final byte[] keyData;
        final String to;
        final Map<String,String> parameters;

        private InbomeHeader(Map<String, String> parameters, String to, byte[] keyData) {
            this.parameters = parameters;
            this.to = to;
            this.keyData = keyData;
        }
    }
}
