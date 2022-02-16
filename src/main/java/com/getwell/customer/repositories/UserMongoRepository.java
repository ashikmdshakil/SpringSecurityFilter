package com.getwell.customer.repositories;

import com.getwell.customer.model.Role;
import com.getwell.customer.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserMongoRepository extends MongoRepository<User, String> {
    User findByMobileNumberAndPasswordAndRolesContaining(String number, String password, Role role);
    User findByMobileNumberAndRolesContaining(String number, Role role);
}
