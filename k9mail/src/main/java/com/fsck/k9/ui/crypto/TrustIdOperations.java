package com.fsck.k9.ui.crypto;


import java.io.InputStream;
import java.util.Date;

import android.content.Intent;

import com.fsck.k9.mailstore.LocalMessage;
import okio.ByteString;
import org.openintents.openpgp.OpenPgpInlineKeyUpdate;
import org.openintents.openpgp.util.OpenPgpApi;


public class TrustIdOperations {
    public TrustIdOperations() {
    }

    boolean addKeyFromOpenPgpHeaderToIntentIfPresent(LocalMessage currentMessage, Intent decryptIntent) {
        byte[] keyData = getOpenPgpKeyBytes(currentMessage);
        if (keyData == null) {
            return false;
        }

        Date messageDate = currentMessage.getSentDate();
        Date internalDate = currentMessage.getInternalDate();
        Date effectiveDate = messageDate.before(internalDate) ? messageDate : internalDate;

        OpenPgpInlineKeyUpdate data = OpenPgpInlineKeyUpdate.createOpenPgpInlineKeyUpdate(keyData, effectiveDate);
        decryptIntent.putExtra(OpenPgpApi.EXTRA_INLINE_KEY_DATA, data);
        return true;
    }

    void processUnsignedMessage(OpenPgpApi openPgpApi, LocalMessage currentMessage) {
        Intent intent = new Intent(OpenPgpApi.ACTION_UPDATE_TRUST_ID);
        boolean hasInlineKeyData = addKeyFromOpenPgpHeaderToIntentIfPresent(currentMessage, intent);
        if (hasInlineKeyData) {
            String trustId = currentMessage.getFrom()[0].getAddress();
            intent.putExtra(OpenPgpApi.EXTRA_TRUST_IDENTITY, trustId);
            openPgpApi.executeApi(intent, (InputStream) null, null);
        }
    }

    private byte[] getOpenPgpKeyBytes(LocalMessage currentMessage) {
        String[] header = currentMessage.getHeader("OpenPGP");
        if (header.length == 0) {
            return null;
        }

        String openPgpHeaderData = header[0];
        return ByteString.decodeBase64(openPgpHeaderData).toByteArray();
    }

    boolean hasOpenPgpHeader(LocalMessage currentMessage) {
        return currentMessage.getHeader("OpenPGP").length > 0;
    }
}
