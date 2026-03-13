package cncs.academy.ess.repository.memory;

import cncs.academy.ess.model.User;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryUserRepositoryTest {

    @Test
    void save_and_findById_shouldWork() {
        InMemoryUserRepository repo = new InMemoryUserRepository();
        User u = new User(0, "alice", "123"); // ajusta se o teu construtor for diferente

        int id = repo.save(u);
        assertTrue(id > 0);

        User loaded = repo.findById(id);
        assertNotNull(loaded);
        assertEquals("alice", loaded.getUsername());
    }

    @Test
    void findAll_shouldReturnAllUsers() {
        InMemoryUserRepository repo = new InMemoryUserRepository();
        repo.save(new User(0, "u1", "p1"));
        repo.save(new User(0, "u2", "p2"));

        List<User> all = repo.findAll();
        assertEquals(2, all.size());
    }

    @Test
    void deleteById_shouldRemoveUser() {
        InMemoryUserRepository repo = new InMemoryUserRepository();
        int id = repo.save(new User(0, "bob", "p"));

        assertNotNull(repo.findById(id));
        repo.deleteById(id);
        assertNull(repo.findById(id));
    }

    @Test
    void findByUsername_shouldReturnMatchingUser_orNull() {
        InMemoryUserRepository repo = new InMemoryUserRepository();
        repo.save(new User(0, "ricardo", "p"));

        assertNotNull(repo.findByUsername("ricardo"));
        assertNull(repo.findByUsername("nao_existe"));
    }
}
