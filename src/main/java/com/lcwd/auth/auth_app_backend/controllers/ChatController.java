package com.lcwd.auth.auth_app_backend.controllers;

import com.lcwd.auth.auth_app_backend.entity.Tut;
import com.lcwd.auth.auth_app_backend.service.ChatService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping
public class ChatController {

//    private ChatClient openAiChatClient;
//    private ChatClient ollamaChatClient;
//
//    public ChatController(@Qualifier("openAiChatClient") ChatClient openAiChatClient,@Qualifier("ollamaChatClient") ChatClient ollamaChatClient) {
//        this.openAiChatClient = openAiChatClient;
//        this.ollamaChatClient = ollamaChatClient;
//    }

//    private ChatClient chatClient;

    private ChatService chatService;

//    public ChatController(ChatClient.Builder chatClientBuilder) {
//        this.chatClient = chatClientBuilder.build();
//    }

    public ChatController(ChatService chatService) {
        this.chatService = chatService;
    }

    @GetMapping("/chat")
    public ResponseEntity<String> chat(
            @RequestParam(value = "q", required = true) String q){

        return ResponseEntity.ok(chatService.chat(q));
    }
}
