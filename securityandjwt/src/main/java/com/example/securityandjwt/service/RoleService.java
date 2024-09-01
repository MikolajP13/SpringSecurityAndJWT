package com.example.securityandjwt.service;

import com.example.securityandjwt.model.Role;
import com.example.securityandjwt.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public void initializeRoles() {
        Role admin = new Role();
        Role user = new Role();
        Role guest = new Role();
        admin.setRole("ROLE_ADMIN");
        user.setRole("ROLE_USER");
        guest.setRole("ROLE_GUEST");

        this.roleRepository.save(admin);
        this.roleRepository.save(user);
        this.roleRepository.save(guest);
    }
}
