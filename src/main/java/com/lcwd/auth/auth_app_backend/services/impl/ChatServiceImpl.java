package com.lcwd.auth.auth_app_backend.services.impl;

import com.lcwd.auth.auth_app_backend.services.ChatService;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.SimpleLoggerAdvisor;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.ai.chat.prompt.SystemPromptTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ChatServiceImpl implements ChatService {

    public ChatClient chatClient;

    @Value("classpath:/prompts/user-message.st")
    private Resource userMessage;

    @Value("classpath:/prompts/system-message.st")
    private Resource systemMessage;

    public ChatServiceImpl(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @Override
    public String chat(String query) {

        Prompt prompt1 = new Prompt(query);

        String queryStr = "As an expert in coding and programming. Always write program in JAVA. Now reply for this question : {query}";

        return chatClient
                .prompt(query)
                .user(u -> u.text(queryStr).param("query", query))
                .call()
                .content();
    }

    @Override
    public String chatTemplate() {
        return this.chatClient
                .prompt()
//                .advisors(new SimpleLoggerAdvisor())
                .system(system-> system.text(this.systemMessage))
                .user(user->user.text(this.userMessage).param("concept", "Spring controller examples"))
                .call()
                .content();
    }
}
