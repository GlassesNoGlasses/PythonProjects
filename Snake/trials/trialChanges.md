# Trial Changes To Yield Respective Trial Results

### Trial 1:
- Keep same as original commit.

### distance_reward1:
- snake.py:
    - reward += 1 for is_facing
    - reward += 1 for closer distance to food

### distance_reward2:
- snake.py:
    - rewards += 2 for is_facing
    - rewards += 4 for closer distance
    - GAME_OVER_REWARD = -40

### collision_distance_trail1:
- snake.py
    - updated distance_reward to add basic distance reward calculations
    - added get_collision_distance to get the distance between snake head direction and collision object
    - added caluclate_collision_reward to calculate reward bonus based on get_collision_distance
    - GAME_OVER_REWARD = -100
    - FOOD_REWARD = 60 

### move_limit_trial1:
- snake.py
    - added constant MOVE_LIMIT = 60
    - added update_move_counter() to return reward based on current move limit


### updated_distance_reward_1:
- snake.py
    - added constance DISTANCE_REWARD = 500
    - updated distance_reward() with to base reward off of how close player is to food.
- Notes:
    - Agent did not perform as well with new update.
        - Perhaps due to overfitting complexity.
