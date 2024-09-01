package com.example.securityandjwt.service;

import com.example.securityandjwt.DTO.NewUserDTO;
import com.example.securityandjwt.model.Role;
import com.example.securityandjwt.model.User;
import com.example.securityandjwt.repository.RoleRepository;
import com.example.securityandjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public void createAdmin(NewUserDTO userDTO) {
        User admin = this.setData(userDTO);
        Optional<Role> roleAdmin = this.roleRepository.findByRole("ROLE_ADMIN");

        if(roleAdmin.isPresent()) {
            admin.getRoles().add(roleAdmin.get());
            this.userRepository.save(admin);
        }
    }

    public void createUser(NewUserDTO userDTO) {
        User user = this.setData(userDTO);
        Optional<Role> roleUser = this.roleRepository.findByRole("ROLE_USER");

        if(roleUser.isPresent()) {
            user.getRoles().add(roleUser.get());
            this.userRepository.save(user);
        }
    }

    public void createGuest(NewUserDTO userDTO) {
        User guest = this.setData(userDTO);
        Optional<Role> roleGuest = this.roleRepository.findByRole("ROLE_GUEST");

        if(roleGuest.isPresent()) {
            guest.getRoles().add(roleGuest.get());
            this.userRepository.save(guest);
        }
    }

    private User setData(NewUserDTO userDTO) {
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        return user;
    }
}
