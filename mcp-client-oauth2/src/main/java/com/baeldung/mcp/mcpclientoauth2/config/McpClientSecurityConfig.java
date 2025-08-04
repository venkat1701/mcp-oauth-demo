package com.baeldung.mcp.mcpclientoauth2.config;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

import com.baeldung.mcp.mcpclientoauth2.McpSyncClientExchangeFilterFunction;

import io.modelcontextprotocol.client.McpSyncClient;

@Configuration
@EnableWebSecurity
public class McpClientSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .oauth2Client(Customizer.withDefaults())
            .csrf(CsrfConfigurer::disable)
            .build();
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientRepository authorizedClientRepository) {

        OAuth2AuthorizedClientProvider authorizedClientProvider =
            OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .clientCredentials()
                .refreshToken()
                .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
            new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    public WebClient.Builder webClientBuilder(McpSyncClientExchangeFilterFunction filterFunction) {
        return WebClient.builder().apply(filterFunction.configuration());
    }

    @Bean
    public ChatClient chatClient(ChatClient.Builder chatClientBuilder, List<McpSyncClient> mcpClients) {
        return chatClientBuilder
            .defaultToolCallbacks(new SyncMcpToolCallbackProvider(mcpClients))
            .build();
    }

    @Bean
    public McpSyncClientExchangeFilterFunction mcpSyncClientExchangeFilterFunction(
        @Qualifier("authorizedClientManager") OAuth2AuthorizedClientManager clientManager,
        ClientRegistrationRepository clientRegistrationRepository) {
        return new McpSyncClientExchangeFilterFunction(clientManager, clientRegistrationRepository);
    }

}