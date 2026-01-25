package com.lcwd.auth.auth_app_backend.service;

import com.lcwd.auth.auth_app_backend.entity.Tut;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ChatServiceImpl implements ChatService {

    public ChatClient chatClient;

    public ChatServiceImpl(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @Override
    public String chat(String query) {
//        String prompt="about Virat kolhi?";

//        String content = chatClient
//                .prompt()
//                .user(prompt)
//                .system("As an expert in cricket.")
//                .call()
//                .content();

        Prompt prompt1 =new Prompt(query, OllamaChatOptions.builder()
                .model("codellama:latest")
                .temperature(0.3)
                .build());

        var tutorials = chatClient
                .prompt(query)
                .call()
                .content();

        return tutorials;
    }

}
