package com.fsck.k9.ui.crypto;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import com.fsck.k9.mail.MessagingException;
import com.fsck.k9.mail.internet.BinaryTempFileBody;
import com.fsck.k9.mail.internet.MimeMessage;
import com.fsck.k9.ui.crypto.InbomeOperations.InbomeHeader;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;


@RunWith(RobolectricTestRunner.class)
@Config(manifest = Config.NONE, sdk = 21)
public class InbomeOperationsTest {
    InbomeOperations inbomeOperations = new InbomeOperations();

    @Before
    public void setUp() throws Exception {
        BinaryTempFileBody.setTempDirectory(RuntimeEnvironment.application.getCacheDir());
    }

    // Test cases taken from: https://github.com/mailencrypt/inbome/tree/master/src/tests/data

    @Test
    public void getValidInbomeHeader__withNoHeader__shouldReturnNull() throws Exception {
        MimeMessage message = parseFromResource("inbome/no_inbome.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNull(inbomeHeader);
    }

    @Test
    public void getValidInbomeHeader__withBrokenBase64__shouldReturnNull() throws Exception {
        MimeMessage message = parseFromResource("inbome/rsa2048-broken-base64.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNull(inbomeHeader);
    }

    @Test
    public void getValidInbomeHeader__withSimpleInbome() throws Exception {
        MimeMessage message = parseFromResource("inbome/rsa2048-simple.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNotNull(inbomeHeader);
        assertEquals("alice@testsuite.autocrypt.org", inbomeHeader.to);
        assertEquals(0, inbomeHeader.parameters.size());
        assertEquals(1225, inbomeHeader.keyData.length);
    }

    @Test
    public void getValidInbomeHeader__withExplicitType() throws Exception {
        MimeMessage message = parseFromResource("inbome/rsa2048-explicit-type.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNotNull(inbomeHeader);
        assertEquals("alice@testsuite.autocrypt.org", inbomeHeader.to);
        assertEquals(0, inbomeHeader.parameters.size());
    }

    @Test
    public void getValidInbomeHeader__withUnknownType__shouldReturnNull() throws Exception {
        MimeMessage message = parseFromResource("inbome/unknown-type.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNull(inbomeHeader);
    }

    @Test
    public void getValidInbomeHeader__withUnknownCriticalHeader__shouldReturnNull() throws Exception {
        MimeMessage message = parseFromResource("inbome/rsa2048-unknown-critical.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNull(inbomeHeader);
    }

    @Test
    public void getValidInbomeHeader__withUnknownNonCriticalHeader() throws Exception {
        MimeMessage message = parseFromResource("inbome/rsa2048-unknown-non-critical.eml");

        InbomeHeader inbomeHeader = inbomeOperations.getValidInbomeHeader(message);

        assertNotNull(inbomeHeader);
        assertEquals("alice@testsuite.autocrypt.org", inbomeHeader.to);
        assertEquals(1, inbomeHeader.parameters.size());
        assertEquals("ignore", inbomeHeader.parameters.get("_monkey"));
    }

    private MimeMessage parseFromResource(String resourceName) throws IOException, MessagingException {
        InputStream inputStream = readFromResourceFile(resourceName);
        return MimeMessage.parseMimeMessage(inputStream, false);
    }

    private InputStream readFromResourceFile(String name) throws FileNotFoundException {
        return new FileInputStream(RuntimeEnvironment.application.getPackageResourcePath() + "/src/test/resources/" + name);
    }


}