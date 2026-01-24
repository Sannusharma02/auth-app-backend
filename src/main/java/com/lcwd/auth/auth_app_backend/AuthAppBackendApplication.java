package com.lcwd.auth.auth_app_backend;

import com.lcwd.auth.auth_app_backend.auth.config.AppConstants;
import com.lcwd.auth.auth_app_backend.auth.entities.Role;
import com.lcwd.auth.auth_app_backend.auth.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.UUID;

@SpringBootApplication
public class AuthAppBackendApplication implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(AuthAppBackendApplication.class, args);
	}

    @Override
    public void run(String... args) throws Exception {

        //we will create some default user roles
        //ADMIN
        //GUEST

        roleRepository.findByName("ROLE_"+AppConstants.ADMIN_ROLE).ifPresentOrElse( role -> {
//            System.out.println(role.getName());
        }, () -> {
            Role role = new Role();
            role.setName("ROLE_" + AppConstants.ADMIN_ROLE);
            role.setId(UUID.randomUUID());
            roleRepository.save(role);
        });

        roleRepository.findByName("ROLE_"+AppConstants.GUEST_ROLE).ifPresentOrElse( role -> {
//            System.out.println(role.getName());
        }, () -> {
            Role role = new Role();
            role.setName("ROLE_" + AppConstants.GUEST_ROLE);
            role.setId(UUID.randomUUID());
            roleRepository.save(role);
        });

    }

}
