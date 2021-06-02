package com.sysarch.finals.springridersbuddy.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sysarch.finals.springridersbuddy.model.ERole;
import com.sysarch.finals.springridersbuddy.model.Role;
import com.sysarch.finals.springridersbuddy.model.User;
import com.sysarch.finals.springridersbuddy.payload.request.LoginRequest;
import com.sysarch.finals.springridersbuddy.payload.request.SignupRequest;
import com.sysarch.finals.springridersbuddy.payload.request.UpdateRequest;
import com.sysarch.finals.springridersbuddy.payload.response.JwtResponse;
import com.sysarch.finals.springridersbuddy.payload.response.MessageResponse;
import com.sysarch.finals.springridersbuddy.repository.RoleRepository;
import com.sysarch.finals.springridersbuddy.repository.UserRepository;
import com.sysarch.finals.springridersbuddy.security.jwt.JwtUtils;
import com.sysarch.finals.springridersbuddy.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity
				.ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getFirstname(), userDetails.getLastname(),
						userDetails.getUsername(), userDetails.getEmail(), userDetails.getPassword(), roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

		String firstname = signUpRequest.getFirstname();
		String lastname = signUpRequest.getLastname();

		//check if number exist in a string
		char[] chars_firstname = firstname.toCharArray();
		char[] chars_lastname = lastname.toCharArray();

		for(char c : chars_firstname){
			if(Character.isDigit(c)){
				return ResponseEntity.badRequest().body(new MessageResponse("Invalid first name value numbers are not allowed"));
			}
		}

		for(char c : chars_lastname){
			if(Character.isDigit(c)){
				return ResponseEntity.badRequest().body(new MessageResponse("Invalid last name value numbers are not allowed"));
			}
		}

		//check if input is a number
		if (Pattern.matches("[0-9]+", firstname) == true) {
			return ResponseEntity.badRequest().body(new MessageResponse("First name value won't allow numbers!"));
		}

		if (Pattern.matches("[0-9]+", lastname) == true) {
			return ResponseEntity.badRequest().body(new MessageResponse("Last name value won't allow numbers!"));
		}
		
		//check if special characters exist
		Pattern pattern_firstname = Pattern.compile("[^a-zA-Z0-9]");
		Matcher matcher_firstname = pattern_firstname.matcher(firstname);

		boolean isContainSpecialCharactersForFirstname = matcher_firstname.find();

		if(isContainSpecialCharactersForFirstname) {
			return ResponseEntity.badRequest().body(new MessageResponse("First name value won't allow special characters!"));
		}

		Pattern pattern_lastname = Pattern.compile("[^a-zA-Z0-9]");
		Matcher matcher_lastname = pattern_lastname.matcher(lastname);

		boolean isContainSpecialCharactersForLastName = matcher_lastname.find();

		if(isContainSpecialCharactersForLastName) {
			return ResponseEntity.badRequest().body(new MessageResponse("Last name value won't allow special characters!"));
		}

		//check if username and email exist
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getFirstname(), signUpRequest.getLastname(), signUpRequest.getUsername(),
				signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRoles();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
					case "admin":
						Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(adminRole);

						break;
					default:
						Role userRole = roleRepository.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("Welcome to Riders Buddy, we are happy to have you!"));
	}

	@PutMapping("/update")
	public ResponseEntity<?> updateUser(@Valid @RequestBody UpdateRequest updateRequest) {

		String userID = updateRequest.getId();
		
		Optional<User> userData = userRepository.findById(userID);

		if (userRepository.existsByUsername(updateRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
		}

		if (userRepository.existsByEmail(updateRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Email is already in use!"));
		}

		if (userData.isPresent()) {
			User _users = (User) userData.get();
			_users.setFirstname(updateRequest.getFirstname());
			_users.setLastname(updateRequest.getLastname());
			_users.setUsername(updateRequest.getUsername());
			_users.setEmail(updateRequest.getEmail());
			_users.setPassword(encoder.encode(updateRequest.getPassword()));

			userRepository.save(_users);
			return ResponseEntity.ok(new MessageResponse("Updated Successfully!"));

		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
	}
}
