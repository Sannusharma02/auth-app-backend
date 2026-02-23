package com.lcwd.auth.auth_app_backend.config;

import com.lcwd.auth.auth_app_backend.advisors.TokenPrintAdvisor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.SafeGuardAdvisor;
import org.springframework.ai.chat.client.advisor.SimpleLoggerAdvisor;
import org.springframework.ai.ollama.OllamaChatModel;
//import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class AiConfig {

    @Bean
    public ChatClient chatClient(ChatClient.Builder builder) {
        return builder
//                .defaultAdvisors( new TokenPrintAdvisor(),new SimpleLoggerAdvisor(), new SafeGuardAdvisor(List.of("games")))
                .defaultAdvisors( new TokenPrintAdvisor(), new SafeGuardAdvisor(List.of("games")))
                .defaultSystem("You are a helpful coding assistant. You are an expert in coding.")
                .defaultOptions(OllamaChatOptions.builder()
                                .model("codellama:latest")
                                .temperature(0.3)
                                .build())
                .build();
    }
}
