#include "afl-fuzz.h"

#include <jsoncpp/json/json.h>
#include <fstream>
#include <algorithm>
#include <sys/time.h>
#include <map>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>



#ifdef __cplusplus
extern "C" {
#endif 

std::map<u32, std::map<u32, u32>> func_dist_map;
u8 unvisited_func_map[FUNC_SIZE], iterated_func_map[FUNC_SIZE];

std::vector<u32> seed_length;


/* initialize loading static maps */

void initialized_dist_map() {

  Json::Value shortest_dist_map;
  Json::Reader reader;
  std::string temporary_dir = std::getenv("TMP_DIR"), errs;
  std::ifstream dist_map(temporary_dir + "/calldst.json", std::ifstream::binary);
  
  if (!reader.parse(dist_map, shortest_dist_map, false))
    PFATAL("Failed loading dist map !");

  for (auto dst_s : shortest_dist_map.getMemberNames()) {

    std::map<u32, u32> func_shortest;
    Json::Value func_shortest_value = shortest_dist_map[dst_s];
    
    for (auto src_s : func_shortest_value.getMemberNames()) {
  
      func_shortest.insert(std::make_pair(std::stoi(src_s), func_shortest_value[src_s].asInt()));
  
    }
    
    func_dist_map.insert(std::make_pair(std::stoi(dst_s), func_shortest));
  
  }

  for (int i = 0; i < FUNC_SIZE; i ++) unvisited_func_map[i] = 1;
  
}


void write_function_log(afl_state_t *afl, struct queue_entry *q1, struct queue_entry *q2,
                        u32 dist1, u32 dist2, u32 func_id) {
  
  if (!afl->function_debug_log) {
    
    afl->function_debug_log = (u8*)malloc(strlen((const char *)afl->out_dir) + 17);//alloc_printf("%s/func_debug.log", afl->out_dir);
    sprintf((char *)afl->function_debug_log, "%s/func_debug.log", afl->out_dir);
    afl->function_debug_fd = fopen((char *)afl->function_debug_log, "w");

  }

  if (q2) {

    // u64 current_ms = get_cur_time_us() / 1000 - afl->start_time;

    fprintf(afl->function_debug_fd, "for function %d, update to s%d, distance %d.\n",
            // current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60,
            func_id, q2->id, dist2);
    // std::cout << "for function " <<  func_id << ", update to s" << q2->id << ", distance " << dist2 << ".\n";
  
  }
  

}

static u64 get_cur_time_cxx(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* wrapper to update top_rated_explore */
void update_bitmap_score_explore(afl_state_t *afl) {

  if (!afl->virgin_funcs) return ;

  if (!afl->shortest_dist) {
    
    afl->shortest_dist = (u32 *)ck_alloc(sizeof(u32) * FUNC_SIZE);

    for (u32 i = 0; i < FUNC_SIZE; i ++) afl->shortest_dist[i] = UNREACHABLE_DIST;
  
  }

  // we only explore each seeds once, so if there are no new seeds, we don't update
  if (afl->last_explored_item == afl->queued_items && afl->last_explored_item) return ;

  for (u32 sid = afl->last_explored_item; sid < afl->queued_items; sid ++) {

    struct queue_entry *q = afl->queue_buf[sid];
    u8 has_new_func = 0;

    if (q->fuzz_level || !q->trace_func) continue;

    for (u32 i = 0; i < FUNC_SIZE; i ++) {

      if (unlikely(q->trace_func[i]) && unlikely(!iterated_func_map[i])) { has_new_func = 1; break; }
        
    }

    if (!has_new_func) continue;

    u64 fav_factor = q->len * q->exec_us;

    for (u32 dst_func = 0; dst_func < FUNC_SIZE; dst_func ++) {

      if (!unvisited_func_map[dst_func] || afl->virgin_funcs[dst_func]) continue;

      // now we don't remove explored functions 
      // if (afl->top_rated_explore[dst_func]) {

      //   if (afl->top_rated_explore[dst_func]->fuzz_level) afl->top_rated_explore[dst_func] = NULL;
      
      // }
      u32 fexp_score = 0, shortest_dist = UNREACHABLE_DIST, src_func = 0;

      for (auto iter = func_dist_map[dst_func].begin(); iter != func_dist_map[dst_func].end(); iter ++) {
      
        if (q->trace_func[iter->first]) {

          if (iter->second < shortest_dist) { src_func = iter->first; shortest_dist = iter->second; }
        
        }
      
      }

      if (shortest_dist != UNREACHABLE_DIST) fexp_score = shortest_dist * 100;

      if (fexp_score) {

        if (!afl->top_rated_explore[dst_func]) {
        
          // write_function_log(afl, afl->top_rated_explore[dst_func], q, afl->shortest_dist[dst_func], fexp_score / 100, i);
          afl->top_rated_explore[dst_func] = q; afl->shortest_dist[dst_func] = fexp_score;
          afl->last_func_time = get_cur_time_cxx(); afl->skip_inter_func = 0;
        
        }
        else {
        
          if (fexp_score < afl->shortest_dist[dst_func]) {
            
            // write_function_log(afl, afl->top_rated_explore[dst_func], q, afl->shortest_dist[dst_func], fexp_score / 100, i);
            afl->top_rated_explore[dst_func] = q; afl->shortest_dist[dst_func] = fexp_score;
            afl->last_func_time = get_cur_time_cxx(); afl->skip_inter_func = 0;

          }
          // if it's a same distance seed with smaller execution speed, only replace if this seed is not fuzzed
          if (fexp_score == afl->shortest_dist[dst_func]) {

            if (!afl->top_rated_explore[dst_func]->fuzz_level) {
              if (fav_factor < afl->top_rated_explore[dst_func]->exec_us * afl->top_rated_explore[dst_func]->len) {
              
                // write_function_log(afl, afl->top_rated_explore[dst_func], q, afl->shortest_dist[dst_func], fexp_score / 100, i);
                afl->top_rated_explore[dst_func] = q; afl->shortest_dist[dst_func] = fexp_score;
                afl->last_func_time = get_cur_time_cxx(); afl->skip_inter_func = 0;

              }
            }
          }

        }
      
      }
    
    }

    for (u32 i = 0; i < FUNC_SIZE; i ++) {

      if (unlikely(q->trace_func[i])) iterated_func_map[i] = 1;
      
    } 

  }

  if (afl->last_explored_item) 
    for (u32 i = 0; i < afl->last_explored_item; i ++) {

      if (afl->queue_buf[i]->trace_func) {
        
        // avoid consuming too much memory
        ck_free(afl->queue_buf[i]->trace_func);
        afl->queue_buf[i]->trace_func = NULL;

      }

    }

  afl->last_explored_item = afl->queued_items;

}


/* wrapper to update exploit threshould */
void target_ranking(afl_state_t *afl) {

  std::vector<std::uint32_t> reached_bugs;
  std::uint32_t max_value = 1;

  if (!afl->reach_bits_count || !afl->trigger_bits_count) return ;

  for (u32 i = 0; i < afl->fsrv.map_size; i ++) {
    
    if (afl->reach_bits_count[i] && !afl->trigger_bits_count[i]) {
      
      reached_bugs.push_back(afl->reach_bits_count[i]);
      
      if (max_value < afl->reach_bits_count[i]) max_value = afl->reach_bits_count[i];
    
    }
  
  }

  std::sort(reached_bugs.begin(), reached_bugs.end());
  if (max_value != 1) {

    float rate = afl->pending_not_fuzzed / afl->queued_items;
    
    if (rate < 0.2) rate = 0.1;
    
    else if (rate < 0.5) rate = 0.075;
    
    else rate = 0.05;
    
    afl->exploit_threshould = reached_bugs[reached_bugs.size() * rate];
  
  }


}

void add_to_vector(u32 length) {
  seed_length.push_back(length);
}

u32 get_pos_length(u32 pos) {
  sort(seed_length.begin(), seed_length.end());
  return seed_length[pos];
}

#ifdef __cplusplus
}
#endif 
