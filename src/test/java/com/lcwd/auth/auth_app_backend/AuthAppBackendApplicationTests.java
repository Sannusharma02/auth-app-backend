package com.lcwd.auth.auth_app_backend;

import com.lcwd.auth.auth_app_backend.services.ChatService;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.PromptTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
class AuthAppBackendApplicationTests {

	@Test
	void contextLoads() {
        var promptTemplate = PromptTemplate.builder()
                .resource(null)
                .build();
        var rendered = promptTemplate.render(Map.of("var1", "Hello World!"));
        System.out.println(rendered);
	}

    @Autowired
    private ChatService chatService;

    @Test
    void testTemplateRender() {
        System.out.println("testTemplateRender");
        var output = this.chatService.chatTemplate();
        System.out.println(output);
    }

}
