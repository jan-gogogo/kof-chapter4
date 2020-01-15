#include "utils.hpp"
using namespace eosio;
using namespace std;

CONTRACT kingofighter : public contract {
  public:
    using contract::contract;
    kingofighter(eosio::name receiver, eosio::name code, datastream<const char*> ds):contract(receiver, code, ds)
    {}

    [[eosio::action]]
    void signup(const name player);
    
    [[eosio::action]]
    void battle(const uint64_t& game_id,const string &house_seed);
    
    void transfer(const name from,const name to,const asset &quantity, const string memo);
  
  private:
 
    //player
    //scope is self
    TABLE players {
      name player_account;
      asset coin;
      uint64_t counter;
      uint64_t created_at;
        
      uint64_t primary_key() const { return player_account.value;}
    };
    
    //hero
    //scope is player 
     TABLE heros {
      uint64_t id;
      string hero_name;
      uint32_t min_atk;
      uint32_t max_atk;
      uint32_t hp;
      uint64_t created_at;
      
      uint64_t primary_key() const { return id;}
    };

    //games
    //scope is self 
     TABLE games {
      uint64_t game_id;
      name player_account;
      string user_seed;
      checksum256 house_seed_hash;
      uint64_t expire_timestamp;
      asset coin;
      signature sig;
      uint64_t status; // 1:等待处理；2：已处理；
      uint64_t created_at;
      
      uint64_t primary_key() const { return game_id;}
      uint64_t get_hsh() const { return uint64_hash(house_seed_hash);}
      uint64_t get_status() const { return status;}
    };
    
     //box
     //scope is self
     //index: player_account
     TABLE boxs {
      uint64_t id;
      name player_account;
      uint8_t level;
      uint64_t created_at;
      
      uint64_t get_player() const { return player_account.value;}
      uint64_t primary_key() const { return id;}
    };
    
    struct scoreboard{
      uint64_t round_no;
      name attacker;
      name defender;
      uint32_t damage;
      uint64_t defender_hp;
    };
    
    //game records
    //scope is self
    //index: player_account
    TABLE gamerecords {
      uint64_t game_id;
      name player_account;
      uint64_t player_counter;
      vector<scoreboard> scoreboards;
      string game_result;
      uint64_t created_at;
      
      uint64_t get_player() const { return player_account.value;}
      uint64_t primary_key() const { return game_id;}
    };
    
   using player_index = multi_index<"players"_n, players>;
   using hero_index = multi_index<"heros"_n, heros>;
   using game_index = multi_index<"games"_n, games,
   indexed_by<"byhsh"_n, const_mem_fun<games, uint64_t, &games::get_hsh>>,
   indexed_by<"bystatus"_n, const_mem_fun<games, uint64_t, &games::get_status>>
    >;
   using box_index = multi_index<"boxs"_n, boxs,
    indexed_by<"byplayer"_n, const_mem_fun<boxs, uint64_t, &boxs::get_player>>
    >;
   using game_record_index = multi_index<"gamerecords"_n, gamerecords,
    indexed_by<"byplayer"_n, const_mem_fun<gamerecords, uint64_t, &gamerecords::get_player>>
    >;

};

extern "C"
{
  void apply(uint64_t receiver, uint64_t code, uint64_t action) {
      if (code == name("kofgametoken").value && action == name("transfer").value) {
          execute_action(name(receiver), name(code), &kingofighter::transfer);
          return;
      }
      
      if (code != receiver)
          return;
  
      switch (action) {
          EOSIO_DISPATCH_HELPER(kingofighter, (signup)(battle))
      }
    eosio_exit(0);
  }
}

