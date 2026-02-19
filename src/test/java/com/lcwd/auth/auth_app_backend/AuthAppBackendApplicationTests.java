package com.lcwd.auth.auth_app_backend;

import com.lcwd.auth.auth_app_backend.auth.services.UserService;
import com.lcwd.auth.auth_app_backend.auth.services.impl.UserServiceImpl;
import com.lcwd.auth.auth_app_backend.services.ChatService;
import com.lcwd.auth.auth_app_backend.services.impl.ChatServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuthAppBackendApplicationTests {

	@Test
	void contextLoads() {
	}

    @Autowired
    private ChatService chatService;
    @Test
    void testTemplateRender() {
        var output = this.chatService.chatTemplate();
        System.out.println(output);
    }

}
