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

        Prompt prompt1 =new Prompt(query);
        //modify this prompt and extra things to prompt make it more interactive

        String queryStr = "As an expert in coding and programming. Always write program in JAVA. Now reply for this question : {query}";

        //prompt template
        // promot
        //get prompt from resources
        var tutorials = chatClient
                .prompt()
                .user(u-> u.text(queryStr).param("query",query))
                .call()
                .content();

        return tutorials;
    }

}
