import argon2 from 'argon2';

// hash password
export const hashPassword = async (plainPassword: string): Promise<string> => {
    return argon2.hash(plainPassword, {
        type: argon2.argon2id, // best variant
        memoryCost: 2 ** 16, // 64 MB
        timeCost: 3, // iterations
        parallelism: 1
    });
};


// verify password
export const verifyPassword = async (hashedPassword: string, plainPassword: string): Promise<boolean> => {
    return argon2.verify(hashedPassword, plainPassword);
};