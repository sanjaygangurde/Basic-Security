package com.securirty.jwt;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class LogInRequest {

    private String username;

    private String password;

}
