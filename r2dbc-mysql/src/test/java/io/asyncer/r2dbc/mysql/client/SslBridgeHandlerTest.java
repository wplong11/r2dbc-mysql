/*
 * Copyright 2026 asyncer.io projects
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.asyncer.r2dbc.mysql.client;

import io.asyncer.r2dbc.mysql.ConnectionContextTest;
import io.asyncer.r2dbc.mysql.MySqlConnectionConfigurationTest;
import io.asyncer.r2dbc.mysql.constant.SslMode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import javax.net.ssl.SNIHostName;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class SslBridgeHandlerTest {

    private static final String HOST = "mysql.example.com";

    private static final int PORT = 3306;

    @ParameterizedTest
    @EnumSource(value = SslMode.class,
        names = { "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY", "TUNNEL" })
    void disablesNettyEndpointIdentification(SslMode mode) throws Exception {
        assertThat(SslBridgeHandler.MySqlSslContextSpec
            .forClient(MySqlConnectionConfigurationTest.newSsl(mode), ConnectionContextTest.mock())
            .sslContext().newEngine(ByteBufAllocator.DEFAULT).getSSLParameters()
            .getEndpointIdentificationAlgorithm()).isNull();
    }

    @ParameterizedTest
    @EnumSource(value = SslMode.class,
        names = { "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY", "TUNNEL" })
    void sendsSniForInetSocketAddress(SslMode mode) {
        EmbeddedChannel channel = new RemoteAddressChannel(InetSocketAddress.createUnresolved(HOST, PORT));
        SslHandler sslHandler = bridge(channel, mode);

        assertThat(sslHandler.engine().getPeerHost()).isEqualTo(HOST);
        assertThat(sslHandler.engine().getPeerPort()).isEqualTo(PORT);
        assertThat(sslHandler.engine().getSSLParameters().getServerNames())
            .containsExactly(new SNIHostName(HOST));

        // The ClientHello is written as soon as the SslHandler is added to an active channel, and the
        // only place a plaintext hostname can appear in it is the server_name extension.
        ByteBuf clientHello = readOutbound(channel);
        try {
            assertThat(ByteBufUtil.indexOf(Unpooled.copiedBuffer(HOST, StandardCharsets.US_ASCII), clientHello))
                .isNotNegative();
        } finally {
            clientHello.release();
            finish(channel);
        }
    }

    @Test
    void omitsSniForNonInetSocketAddress() {
        EmbeddedChannel channel = new EmbeddedChannel();
        SslHandler sslHandler = bridge(channel, SslMode.REQUIRED);

        assertThat(sslHandler.engine().getPeerHost()).isNull();
        assertThat(sslHandler.engine().getSSLParameters().getServerNames()).isNullOrEmpty();

        finish(channel);
    }

    private static SslHandler bridge(EmbeddedChannel channel, SslMode mode) {
        channel.pipeline().addLast(SslBridgeHandler.NAME,
            new SslBridgeHandler(ConnectionContextTest.mock(), MySqlConnectionConfigurationTest.newSsl(mode)));

        if (mode != SslMode.TUNNEL) {
            // TUNNEL bridges on handlerAdded, other modes bridge after the server accepts SSL.
            channel.pipeline().fireUserEventTriggered(SslState.BRIDGING);
        }

        SslHandler sslHandler = channel.pipeline().get(SslHandler.class);

        assertThat(sslHandler).isNotNull();

        return sslHandler;
    }

    private static void finish(EmbeddedChannel channel) {
        // Closing the channel fails the pending handshake, which the bridge would turn into an exception.
        channel.pipeline().remove(SslBridgeHandler.NAME);
        channel.finishAndReleaseAll();
    }

    private static ByteBuf readOutbound(EmbeddedChannel channel) {
        ByteBuf outbound = Unpooled.buffer();

        for (ByteBuf buf = channel.readOutbound(); buf != null; buf = channel.readOutbound()) {
            outbound.writeBytes(buf);
            buf.release();
        }

        return outbound;
    }

    /**
     * An {@link EmbeddedChannel} that reports a fixed remote address, like a connected TCP channel does.
     */
    private static final class RemoteAddressChannel extends EmbeddedChannel {

        private final SocketAddress remoteAddress;

        private RemoteAddressChannel(SocketAddress remoteAddress) {
            this.remoteAddress = remoteAddress;
        }

        @Override
        protected SocketAddress remoteAddress0() {
            return remoteAddress;
        }
    }
}
