package com.auth.auth.entities;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Authentication {
	@NotEmpty(message = "Username cannot be empty")
	private String username;

	@NotEmpty(message = "Password cannot be empty")
	private String password;

	@NotEmpty(message = "APIKEY cannot be empty")
	private String apikey;
}
