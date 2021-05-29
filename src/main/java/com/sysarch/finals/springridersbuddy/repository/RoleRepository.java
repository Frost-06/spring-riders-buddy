package com.sysarch.finals.springridersbuddy.repository;

import java.util.Optional;

import com.sysarch.finals.springridersbuddy.model.ERole;
import com.sysarch.finals.springridersbuddy.model.Role;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}
