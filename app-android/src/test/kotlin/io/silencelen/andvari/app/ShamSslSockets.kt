package io.silencelen.andvari.app

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * A platform whose TLS sockets do not do the host-name check they are asked for, over a real factory [real]:
 * - [Mode.DROPS]: the socket does not keep `endpointIdentificationAlgorithm` (reads it back as null), as an old or
 *   broken platform might;
 * - [Mode.LIES]: the socket reports `HTTPS` but never applies it, so the handshake checks no host name.
 */
internal class ShamSslFactory(private val real: SSLSocketFactory, private val mode: Mode) : SSLSocketFactory() {
    enum class Mode { DROPS, LIES }

    override fun getDefaultCipherSuites(): Array<String> = real.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = real.supportedCipherSuites
    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        Sham(real.createSocket(s, host, port, autoClose) as SSLSocket, mode)

    override fun createSocket(host: String?, port: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(host: InetAddress?, port: Int): Socket = throw UnsupportedOperationException()
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()

    private class Sham(private val d: SSLSocket, private val mode: Mode) : SSLSocket() {
        override fun getSSLParameters(): SSLParameters = d.sslParameters.also {
            it.endpointIdentificationAlgorithm = if (mode == Mode.LIES) "HTTPS" else null
        }

        override fun setSSLParameters(params: SSLParameters) {
            params.endpointIdentificationAlgorithm = null
            d.sslParameters = params
        }

        override fun getSupportedCipherSuites(): Array<String> = d.supportedCipherSuites
        override fun getEnabledCipherSuites(): Array<String> = d.enabledCipherSuites
        override fun setEnabledCipherSuites(suites: Array<out String>?) { d.enabledCipherSuites = suites }
        override fun getSupportedProtocols(): Array<String> = d.supportedProtocols
        override fun getEnabledProtocols(): Array<String> = d.enabledProtocols
        override fun setEnabledProtocols(protocols: Array<out String>?) { d.enabledProtocols = protocols }
        override fun getSession(): SSLSession = d.session
        override fun addHandshakeCompletedListener(listener: HandshakeCompletedListener?) = d.addHandshakeCompletedListener(listener)
        override fun removeHandshakeCompletedListener(listener: HandshakeCompletedListener?) = d.removeHandshakeCompletedListener(listener)
        override fun startHandshake() = d.startHandshake()
        override fun setUseClientMode(mode: Boolean) { d.useClientMode = mode }
        override fun getUseClientMode(): Boolean = d.useClientMode
        override fun setNeedClientAuth(need: Boolean) { d.needClientAuth = need }
        override fun getNeedClientAuth(): Boolean = d.needClientAuth
        override fun setWantClientAuth(want: Boolean) { d.wantClientAuth = want }
        override fun getWantClientAuth(): Boolean = d.wantClientAuth
        override fun setEnableSessionCreation(flag: Boolean) { d.enableSessionCreation = flag }
        override fun getEnableSessionCreation(): Boolean = d.enableSessionCreation
        override fun getInputStream(): InputStream = d.inputStream
        override fun getOutputStream(): OutputStream = d.outputStream
        override fun setSoTimeout(timeout: Int) { d.soTimeout = timeout }
        override fun getSoTimeout(): Int = d.soTimeout
        override fun close() = d.close()
        override fun isClosed(): Boolean = d.isClosed
    }
}
