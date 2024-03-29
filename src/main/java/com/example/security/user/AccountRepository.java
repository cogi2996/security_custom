package com.example.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByEmail(String email);// bởi vì email là unique nên chỉ cần tìm kiếm theo email
}
