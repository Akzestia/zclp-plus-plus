use user_data;

CREATE TABLE IF NOT EXISTS UserToUserRelations
(
    Id       UUID,
    lhs_user TEXT,
    rhs_user TEXT
);
