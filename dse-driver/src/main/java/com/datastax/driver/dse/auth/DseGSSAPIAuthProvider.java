/*
 *      Copyright (C) 2012-2016 DataStax Inc.
 *
 *      This software can be used solely with DataStax Enterprise. Please consult the license at
 *      http://www.datastax.com/terms/datastax-dse-driver-license-terms
 */
package com.datastax.driver.dse.auth;

import com.datastax.driver.core.AuthProvider;
import com.datastax.driver.core.Authenticator;
import com.datastax.driver.core.exceptions.AuthenticationException;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableMap;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.net.InetSocketAddress;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Map;


/**
 * {@link AuthProvider} that provides GSSAPI authenticator instances for clients to connect
 * to DSE clusters secured with {@code DseAuthenticator}.
 * <p/>
 * To create a cluster using this auth provider, declare the following:
 * <pre>{@code
 * Cluster cluster = Cluster.builder()
 *                          .addContactPoint(hostname)
 *                          .withAuthProvider(new DseGSSAPIAuthProvider())
 *                          .build();
 * }</pre>
 * <h2>Kerberos Authentication</h2>
 * Keytab and ticket cache settings are specified using a standard JAAS
 * configuration file. The location of the file can be set using the
 * <code>java.security.auth.login.config</code> system property or by adding a
 * <code>login.config.url.n</code> entry in the <code>java.security</code> properties
 * file.
 * <p/>
 * Alternatively a {@link Configuration} object can be provided using {@link #DseGSSAPIAuthProvider(Configuration)} to
 * set the JAAS configuration programmatically.
 * <p/>
 * See the following documents for further details:
 * <ol>
 * <li><a href="https://docs.oracle.com/javase/6/docs/technotes/guides/security/jgss/tutorials/LoginConfigFile.html">JAAS Login Configuration File</a>;</li>
 * <li><a href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html">JAAS Authentication Tutorial</a>
 * for more on JAAS in general.</li>
 * </ol>
 * <h3>Authentication using ticket cache</h3>
 * Run <code>kinit</code> to obtain a ticket and populate the cache before
 * connecting. JAAS config:
 * <pre>
 * DseClient {
 *   com.sun.security.auth.module.Krb5LoginModule required
 *     useTicketCache=true
 *     renewTGT=true;
 * };
 * </pre>
 * <h3>Authentication using a keytab file</h3>
 * To enable authentication using a keytab file, specify its location on disk.
 * If your keytab contains more than one principal key, you should also specify
 * which one to select.
 * <pre>
 * DseClient {
 *     com.sun.security.auth.module.Krb5LoginModule required
 *       useKeyTab=true
 *       keyTab="/path/to/file.keytab"
 *       principal="user@MYDOMAIN.COM";
 * };
 * </pre>
 * <h2>Specifying SASL protocol name</h2>
 * The SASL protocol name used by this auth provider defaults to "<code>{@value #DEFAULT_SASL_PROTOCOL_NAME}</code>".
 * <p/>
 * <strong>Important</strong>: the SASL protocol name should match the username of the
 * Kerberos service principal used by the DSE server.
 * This information is specified in the dse.yaml file by the {@code service_principal} option under the
 * <a href="https://docs.datastax.com/en/datastax_enterprise/4.8/datastax_enterprise/config/configDseYaml.html?scroll=configDseYaml__refKerbSupport">kerberos_options</a>
 * section, and <em>may vary from one DSE installation to another</em> – especially if you
 * installed DSE with an automated package installer.
 * <p/>
 * For example, if your dse.yaml file contains the following:
 * <pre>{@code
 * kerberos_options:
 *     ...
 *     service_principal: cassandra/my.host.com@MY.REALM.COM
 * }</pre>
 * The correct SASL protocol name to use when authenticating against this DSE server is "{@code cassandra}".
 * <p/>
 * Should you need to change the SASL protocol name, use one of the methods below:
 * <ol>
 * <li>Specify the protocol name via one of the following constructors:
 * {@link #DseGSSAPIAuthProvider(String)} or {@link #DseGSSAPIAuthProvider(Configuration, String)};</li>
 * <li>Specify the protocol name with the {@code dse.sasl.protocol} system property when starting your application,
 * e.g. {@code -Ddse.sasl.protocol=cassandra}.</li>
 * </ol>
 * If a non-null SASL protocol name is provided to the aforementioned constructors, that name takes precedence over
 * the contents of the {@code dse.sasl.protocol} system property.
 *
 * @see <a href="https://docs.datastax.com/en/datastax_enterprise/4.8/datastax_enterprise/sec/secUsingKerberos.html">Authenticating a DSE cluster with Kerberos</a>
 */
public class DseGSSAPIAuthProvider implements AuthProvider {

    /**
     * The default SASL protocol name used by this auth provider.
     */
    public static final String DEFAULT_SASL_PROTOCOL_NAME = "dse";

    /**
     * The name of the system property to use to specify the SASL protocol name.
     */
    public static final String SASL_PROTOCOL_NAME_PROPERTY = "dse.sasl.protocol";

    private final Configuration loginConfiguration;

    private final String saslProtocol;

    private final Subject subject;

    /**
     * Creates an instance of {@code DseGSSAPIAuthProvider} with default login configuration options and default
     * SASL protocol name ({@value #DEFAULT_SASL_PROTOCOL_NAME}).
     */
    public DseGSSAPIAuthProvider() {
        this((Configuration) null, null);
    }

    /**
     * Creates an instance of {@code DseGSSAPIAuthProvider} with the given login configuration and default
     * SASL protocol name ({@value #DEFAULT_SASL_PROTOCOL_NAME}).
     *
     * @param loginConfiguration The login configuration to use to create a {@link LoginContext}.
     */
    public DseGSSAPIAuthProvider(Configuration loginConfiguration) {
        this(loginConfiguration, null);
    }

    /**
     * Creates an instance of {@code DseGSSAPIAuthProvider} with default login configuration and the given
     * SASL protocol name.
     *
     * @param saslProtocol The SASL protocol name to use; should match the username of the
     *                     Kerberos service principal used by the DSE server.
     */
    public DseGSSAPIAuthProvider(String saslProtocol) {
        this((Configuration) null, saslProtocol);
    }

    /**
     * Creates an instance of {@code DseGSSAPIAuthProvider} with the given login configuration and the given
     * SASL protocol name.
     *
     * @param loginConfiguration The login configuration to use to create a {@link LoginContext}.
     * @param saslProtocol       The SASL protocol name to use; should match the username of the
     *                           Kerberos service principal used by the DSE server.
     */
    public DseGSSAPIAuthProvider(Configuration loginConfiguration, String saslProtocol) {
        this.loginConfiguration = loginConfiguration;
        this.saslProtocol = saslProtocol;
        this.subject = null;
    }

    public DseGSSAPIAuthProvider(Subject subject) {
        this(subject, null);
    }

    public DseGSSAPIAuthProvider(Subject subject, String saslProtocol) {
        this.loginConfiguration = null;
        this.saslProtocol = saslProtocol;
        this.subject = subject;
    }

    @Override
    public Authenticator newAuthenticator(InetSocketAddress host, String authenticator) throws AuthenticationException {
        if (subject != null) {
            return new GSSAPIAuthenticator(authenticator, host, subject, saslProtocol);
        } else {
            return new GSSAPIAuthenticator(authenticator, host, loginConfiguration, saslProtocol);
        }
    }

    private static class GSSAPIAuthenticator extends BaseDseAuthenticator {
        private static final String JAAS_CONFIG_ENTRY = "DseClient";
        private static final String[] SUPPORTED_MECHANISMS = new String[]{"GSSAPI"};
        private static final Map<String, String> DEFAULT_PROPERTIES =
                ImmutableMap.<String, String>builder().put(Sasl.SERVER_AUTH, "true")
                        .put(Sasl.QOP, "auth")
                        .build();
        private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
        private static final byte[] MECHANISM = "GSSAPI".getBytes(Charsets.UTF_8);
        private static final byte[] SERVER_INITIAL_CHALLENGE = "GSSAPI-START".getBytes(Charsets.UTF_8);

        private final Subject subject;
        private final SaslClient saslClient;

        private GSSAPIAuthenticator(String authenticator, InetSocketAddress host, Configuration loginConfiguration, String saslProtocol) {
            super(authenticator);
            try {
                String protocol = saslProtocol;
                if (protocol == null) {
                    protocol = System.getProperty(SASL_PROTOCOL_NAME_PROPERTY, DEFAULT_SASL_PROTOCOL_NAME);
                }
                LoginContext login = new LoginContext(JAAS_CONFIG_ENTRY, null, null, loginConfiguration);
                login.login();
                subject = login.getSubject();
                saslClient = Sasl.createSaslClient(SUPPORTED_MECHANISMS,
                        null,
                        protocol,
                        host.getAddress().getCanonicalHostName(),
                        DEFAULT_PROPERTIES,
                        null);
            } catch (LoginException e) {
                throw new RuntimeException(e);
            } catch (SaslException e) {
                throw new RuntimeException(e);
            }
        }


        private GSSAPIAuthenticator(String authenticator, InetSocketAddress host, Subject subject, String saslProtocol) {
            super(authenticator);
            try {
                String protocol = saslProtocol;
                if (protocol == null) {
                    protocol = System.getProperty(SASL_PROTOCOL_NAME_PROPERTY, DEFAULT_SASL_PROTOCOL_NAME);
                }
                this.subject = subject;
                saslClient = Sasl.createSaslClient(SUPPORTED_MECHANISMS,
                    null,
                    protocol,
                    host.getAddress().getCanonicalHostName(),
                    DEFAULT_PROPERTIES,
                    null);
            } catch (SaslException e) {
                throw new RuntimeException(e);
            }
        }

        public byte[] getMechanism() {
            return MECHANISM.clone();
        }

        public byte[] getInitialServerChallenge() {
            return SERVER_INITIAL_CHALLENGE.clone();
        }

        public byte[] evaluateChallenge(byte[] challenge) {
            if (Arrays.equals(SERVER_INITIAL_CHALLENGE, challenge)) {
                if (!saslClient.hasInitialResponse()) {
                    return EMPTY_BYTE_ARRAY;
                }
                challenge = EMPTY_BYTE_ARRAY;
            }
            final byte[] internalChallenge = challenge;
            try {
                return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]>() {
                    public byte[] run() throws SaslException {
                        return saslClient.evaluateChallenge(internalChallenge);
                    }
                });
            } catch (PrivilegedActionException e) {
                throw new RuntimeException(e.getException());
            }
        }
    }
}
