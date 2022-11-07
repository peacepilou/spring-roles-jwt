package com.getarrays.userservice.repo;

import com.getarrays.userservice.domain.Role;
import com.getarrays.userservice.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
