package com.lcwd.auth.auth_app_backend.service;

import com.lcwd.auth.auth_app_backend.entity.Tut;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ChatServiceImpl implements ChatService {

    public ChatClient chatClient;

    public ChatServiceImpl(ChatClient.Builder builder) {
        this.chatClient = builder.build();
    }

    @Override
    public List<Tut> chat(String query) {
//        String prompt="about Virat kolhi?";

//        String content = chatClient
//                .prompt()
//                .user(prompt)
//                .system("As an expert in cricket.")
//                .call()
//                .content();

        Prompt prompt1 =new Prompt(query);

        List<Tut> tutorial = chatClient
                .prompt(prompt1)
                .call()
                .entity(new ParameterizedTypeReference<List<Tut>>() {
                });

        return tutorial;
    }

}
