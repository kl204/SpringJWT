package com.example.springjwt.dto;

import com.example.springjwt.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity){

        this.userEntity = userEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {

                return userEntity.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }


    // 이 계정이 만료되지 않았다.= true
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 이 계정이 잠기지 않았다 = true
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 이 계정의 Credential이 만료되지 않았다 = true
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 이 계정이 사용 가능하다 = true
    @Override
    public boolean isEnabled() {
        return true;
    }
}
