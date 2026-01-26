package com.lcwd.auth.auth_app_backend.services.impl;

import com.lcwd.auth.auth_app_backend.services.ChatService;
import org.springframework.ai.chat.client.ChatClient;
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
//        String prompt="about Virat kolhi?";

//        String content = chatClient
//                .prompt()
//                .user(prompt)
//                .system("As an expert in cricket.")
//                .call()
//                .content();

        Prompt prompt1 = new Prompt(query);
        //modify this prompt and extra things to prompt make it more interactive

        String queryStr = "As an expert in coding and programming. Always write program in JAVA. Now reply for this question : {query}";

        //prompt template
        // promot
        //get prompt from resources
        var tutorials = chatClient
                .prompt(query)
                .user(u -> u.text(queryStr).param("query", query))
                .call()
                .content();

        return tutorials;
    }

    @Override
    public String chatTemplate() {

        //first step
//        PromptTemplate strTemplate = PromptTemplate.builder().template("What is {techName}? tell me example of {exampleName}").build();
//
//        //render the template
//        String renderedMessage = strTemplate.render(Map.of(
//                "techName", "Spring",
//                "exampleName", "Spring Boot"
//        ));
//
//        Prompt prompt = new Prompt(renderedMessage);

//2nd

//        var systemPromptTemplate = SystemPromptTemplate.builder()
//                .template("You are a helpful coding assistant. You are an expert in coding.")
//                .build();
//
//        var systemMessage = systemPromptTemplate.createMessage();
//
//        var userPromptTemplate = PromptTemplate.builder().template("What is {techName}? tell me example of {exampleName}").build();
//        var userPromptMessage = userPromptTemplate.createMessage(Map.of(
//                "techName", "Spring",
//                "exampleName", "Spring Boot"
//        ));
//
//        Prompt prompt = new Prompt(systemMessage,userPromptMessage);

        return this.chatClient
                .prompt()
                .system(system->
                        system.text(this.systemMessage)
//                        system.text("You are a helpful coding assistant. You are an expert in coding.")
                )
                .user(
                        user->user.text(this.userMessage)
                                .param("concept", "Spring controller examples")
//                        user-> user.text("What is {techName}? tell me also about {exampleName}")
//                                .param("techName", "Spring controller examples")
//                                .param("exampleName", "Collection framework examples in java")
                )
                .call()
                .content();
    }
}
