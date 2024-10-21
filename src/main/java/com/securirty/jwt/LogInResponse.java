package com.securirty.jwt;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LogInResponse {

    private String jwtToken;

    private String userName;

    private List<String> roles;

}
