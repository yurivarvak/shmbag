
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <stdlib.h>
#include "shmbag.h"

using namespace std;

// UUID stuff
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using namespace boost::uuids;
string get_uuid(int i)
{
  static boost::uuids::name_generator g(boost::uuids::nil_uuid());
  boost::uuids::uuid u(g(&i, sizeof(i)));
  return boost::uuids::to_string(u);
}

void print_item(shmbag_item_t item, const char *msg = 0)
{
  char id[80] = "nil";
  shmbag_item_get_id(item, id);
  if (msg)
    cout << msg << " = ";
  cout << "{ item:" << id << 
    ", size:" << shmbag_item_get_size(item) <<
    ", cap:" << shmbag_item_get_capacity(item) << " }\n";
}

bool simple_test()
{
  cout << "\nSimple test:";
  const char *fname = "simple.shmdata";
  shmbag_mgr_t mgr = shmbag_mgr_open(fname, true); assert(mgr);
  string s = get_uuid(100);
  shmbag_item_t item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(!item);
  item = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), 100); assert(item);
  const char *data = "some text";
  int ret = shmbag_item_append(item, strlen(data) + 1, data); assert(ret == strlen(data) + 1);
  print_item(item, "initial item");
  ret = shmbag_item_free(item); assert(ret == 0);
  ret = shmbag_mgr_close(mgr); assert(ret == 0);
  mgr = shmbag_mgr_open(fname, false);
  item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(item);
  ret = shmbag_item_append(item, strlen(data) + 1, data); assert(ret == strlen(data) + 1);
  print_item(item, "after reopen & update");
  ret = shmbag_mgr_item_realloc(mgr, item, 12854); assert(ret == 0);
  print_item(item, "after realloc");
  ret = shmbag_item_free(item); assert(ret == 0);
  shmbag_item_t item2 = shmbag_mgr_item_acquire_or_alloc(mgr, 0, 33893); assert(item);
  const char *data2 = "other text";
  ret = shmbag_item_append(item2, strlen(data2) + 1, data2);assert(ret == strlen(data2) + 1);
  print_item(item2, "nameless item");
  s = get_uuid(101);
  ret = shmbag_mgr_item_set_id(mgr, item2, s.c_str()); assert(ret == 0);
  print_item(item2, "set item name");
  ret = shmbag_item_free(item2); assert(ret == 0);
  item2 = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), 0); assert(item);
  print_item(item2, "reopen renamed item");
  ret = shmbag_item_free(item2); assert(ret == 0);
  ret = shmbag_mgr_close(mgr); assert(ret == 0);
  return true;
}

void large_test()
{
  cout << "\nLarge test:";
  const char *fname = "large.shmdata";
  const int num_blocks = 10000;
  auto start = chrono::system_clock::now();
  shmbag_mgr_t mgr = shmbag_mgr_open(fname, true); assert(mgr);
  for (int i = 0; i < num_blocks; i++)
  {
    string s = get_uuid(i);
    shmbag_item_t item = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), 100); assert(item);
	int ret = shmbag_item_append(item, s.size() + 1, s.c_str()); assert(ret == s.size() + 1);
    ret = shmbag_item_free(item); assert(ret == 0);
  }
  auto mid = chrono::system_clock::now();
  chrono::duration<double> elapsed_seconds = mid - start;
  cout << "alloc " << elapsed_seconds.count() << "s. ";
  for (int i = 0; i < num_blocks; i++)
  {
    string s = get_uuid(i);
    shmbag_item_t item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(item);
    int ret = shmbag_mgr_item_realloc(mgr, item, (num_blocks - i) * 1 + 1); assert(ret == 0);
	assert(!strcmp(shmbag_item_get_ptr(item), s.c_str()));
    shmbag_item_t item2 = shmbag_item_get(fname, shmbag_item_get_offset(item)); assert(item);
	assert(!strcmp(shmbag_item_get_ptr(item2), s.c_str()));
    ret = shmbag_item_free(item2); assert(ret == 0);
    ret = shmbag_item_free(item); assert(ret == 0);
  }
  int ret = shmbag_mgr_close(mgr); assert(ret == 0);
  auto end = chrono::system_clock::now();
  elapsed_seconds = end - mid;
  cout << " realloc " << elapsed_seconds.count() << "s.\n";
}

void concurrent_test()
{
}

int main()
{
  simple_test();
  large_test();
  return 0;
}
