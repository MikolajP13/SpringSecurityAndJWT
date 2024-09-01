package com.example.securityandjwt;

import com.example.securityandjwt.DTO.AuthenticationRequest;
import com.example.securityandjwt.DTO.NewUserDTO;
import com.example.securityandjwt.security.JwtService;
import com.example.securityandjwt.service.RoleService;
import com.example.securityandjwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class Controller {

    private final UserService userService;
    private final RoleService roleService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @GetMapping("/init-roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void initRoles() {
        this.roleService.initializeRoles();
    }

    @PostMapping("/create-admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void createAdmin(@RequestBody NewUserDTO userDTO) {
        this.userService.createAdmin(userDTO);
    }

    @PostMapping("/create-user")
    public void createUser(@RequestBody NewUserDTO userDTO) {
        this.userService.createUser(userDTO);
    }

    @PostMapping("/create-guest")
    public void createGuest(@RequestBody NewUserDTO userDTO) {
        this.userService.createGuest(userDTO);
    }

    @GetMapping("/all")
    public String forAll() {
        return "FOR ALL";
    }

    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthenticationRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
            if (authentication.isAuthenticated()) {
                return jwtService.generateToken(authRequest.getUsername());
            } else {
                throw new UsernameNotFoundException("Invalid user request!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String forAdmin() {
        return "ADMIN";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String forUser() {
        return "USER";
    }

    @GetMapping("/guest")
    @PreAuthorize("hasAuthority('ROLE_GUEST')")
    public String forGuest() {
        return "GUEST";
    }
}
