package com.lcwd.auth.auth_app_backend.services;

import reactor.core.publisher.Flux;

public interface ChatService {

    String chat(String query);

    public String chatTemplate();

    Flux<String> streamChat(String query);
}
